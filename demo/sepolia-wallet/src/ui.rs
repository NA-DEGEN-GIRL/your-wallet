//! Korean native UI for the standalone Sepolia-only development wallet.
//!
//! This module owns no cryptographic or RPC implementation. Potentially slow
//! work is sent to one backend worker so Argon2 and network calls cannot freeze
//! the `egui` event loop.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
    mpsc::{self, Receiver, Sender, TryRecvError},
};
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};
use zeroize::{Zeroize, Zeroizing};

const MINIMUM_PASSWORD_BYTES: usize = 12;
const SEND_HOLD_DURATION: Duration = Duration::from_secs(2);
const SECRET_REVEAL_DURATION: Duration = Duration::from_secs(20);
const INACTIVITY_LOCK_DURATION: Duration = Duration::from_secs(5 * 60);
const GENERATED_BACKUP_CHALLENGE_WORDS: usize = 4;
const GENERATED_BACKUP_ONE_ATTEMPT_WARNING: &str =
    "확인은 단 한 번만 가능합니다. 불일치하면 이 지갑은 저장되지 않습니다.";

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

/// One saved custom ERC-20 contract and its current Sepolia validation state.
///
/// Deliberately does not implement `Debug`: full contract addresses and token
/// balances are useful in the UI, but unnecessary in diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct CustomTokenSnapshot {
    /// Full checksummed contract address. The UI must always show this value.
    pub contract_address: String,
    /// Current runtime validation result for the saved contract.
    pub state: CustomTokenState,
}

/// Runtime-validated public metadata for one saved custom token.
#[derive(Clone, Eq, PartialEq)]
pub enum CustomTokenState {
    /// Code hash and exact ABI metadata still match the authenticated record.
    Verified {
        /// Untrusted, strictly bounded ASCII symbol returned by the contract.
        symbol: Option<String>,
        /// Exact, strictly decoded ERC-20 decimal count.
        decimals: u8,
        /// Account-0 balance formatted with the verified decimal count.
        balance: String,
    },
    /// Trusted metadata and balance are intentionally omitted after failure.
    Unavailable {
        /// Short category-only Korean explanation without raw RPC data.
        reason_ko: String,
    },
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

/// One-shot generated-wallet display payload. It deliberately has neither
/// `Clone` nor `Debug`; both strings zeroize when the display state is dropped.
pub struct GeneratedBackupReveal {
    phrase: Zeroizing<String>,
    first_address: Zeroizing<String>,
    expires_at: Instant,
}

impl GeneratedBackupReveal {
    #[must_use]
    pub(crate) const fn new(
        phrase: Zeroizing<String>,
        first_address: Zeroizing<String>,
        expires_at: Instant,
    ) -> Self {
        Self {
            phrase,
            first_address,
            expires_at,
        }
    }

    #[must_use]
    fn phrase(&self) -> &str {
        self.phrase.as_str()
    }

    #[must_use]
    fn first_address(&self) -> &str {
        self.first_address.as_str()
    }

    #[must_use]
    pub(crate) const fn expires_at(&self) -> Instant {
        self.expires_at
    }
}

/// Public prompt metadata for the second ceremony stage. Expected words and
/// the account address never cross this boundary.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct GeneratedBackupChallenge {
    positions: [u8; GENERATED_BACKUP_CHALLENGE_WORDS],
    expires_at: Instant,
}

impl GeneratedBackupChallenge {
    #[must_use]
    pub(crate) const fn new(
        positions: [u8; GENERATED_BACKUP_CHALLENGE_WORDS],
        expires_at: Instant,
    ) -> Self {
        Self {
            positions,
            expires_at,
        }
    }

    #[must_use]
    pub(crate) const fn positions(&self) -> [u8; GENERATED_BACKUP_CHALLENGE_WORDS] {
        self.positions
    }

    #[must_use]
    pub(crate) const fn expires_at(&self) -> Instant {
        self.expires_at
    }
}

/// One-shot, zeroizing response to a generated backup challenge. The payload
/// is move-only and has no `Debug` implementation.
pub struct GeneratedBackupConfirmation {
    words: [SensitiveText; GENERATED_BACKUP_CHALLENGE_WORDS],
    first_address: SensitiveText,
}

impl GeneratedBackupConfirmation {
    #[must_use]
    pub(crate) fn new(
        words: [SensitiveText; GENERATED_BACKUP_CHALLENGE_WORDS],
        first_address: SensitiveText,
    ) -> Self {
        Self {
            words,
            first_address,
        }
    }

    #[must_use]
    pub(crate) fn into_zeroizing_parts(
        self,
    ) -> (
        [Zeroizing<String>; GENERATED_BACKUP_CHALLENGE_WORDS],
        Zeroizing<String>,
    ) {
        (
            self.words.map(SensitiveText::into_zeroizing),
            self.first_address.into_zeroizing(),
        )
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

/// Exact backend-normalized saved ERC-20 transfer values shown before signing.
///
/// This deliberately has no `Debug` implementation. The contract, recipient,
/// amount, and fee values are public transaction metadata, but do not belong in
/// diagnostics or crash output.
#[derive(Clone, Eq, PartialEq)]
pub struct Erc20TransferPreview {
    /// Full saved contract address reopened from the authenticated sidecar.
    pub contract_address: String,
    /// Strictly bounded symbol authenticated against the saved metadata.
    pub symbol: Option<String>,
    /// Exact decimal count authenticated against the saved metadata.
    pub decimals: u8,
    /// Exact normalized recipient encoded into `transfer(address,uint256)`.
    pub recipient: String,
    /// Exact normalized human-readable token amount.
    pub amount: String,
    /// Exact pending nonce as an unsigned decimal integer.
    pub nonce: String,
    /// Korean label for the backend-normalized fee selection.
    pub fee_mode_ko: String,
    /// Raw pending-state gas estimate returned for the exact token call.
    pub estimated_gas: String,
    /// Ceil-20%-buffered gas limit frozen for signing, capped at 500,000.
    pub gas_limit: String,
    /// Base fee observed when the quote was prepared, in gwei.
    pub quoted_base_fee_per_gas_gwei: String,
    /// Maximum priority fee per gas in gwei.
    pub max_priority_fee_per_gas_gwei: String,
    /// Maximum total fee per gas in gwei.
    pub max_fee_per_gas_gwei: String,
    /// Network fee estimated from the observed base fee, in ETH.
    pub estimated_network_fee_eth: String,
    /// Maximum ETH network fee for the frozen token gas limit.
    pub max_network_fee_eth: String,
    /// Conservative whole seconds remaining when backend preparation ended.
    pub quote_valid_for_seconds: String,
}

/// Revocable authority for one epoch-bound signing or rebroadcast operation.
///
/// Private fields and a worker-only production constructor prevent another
/// backend from manufacturing an always-current production permit. Callers
/// must make a fresh `is_current` check at every irreversible boundary.
pub struct SessionPermit<'a> {
    expected_epoch: u64,
    active_epoch: &'a AtomicU64,
    #[cfg(test)]
    revoke_on_check: Option<usize>,
    #[cfg(test)]
    check_count: std::sync::atomic::AtomicUsize,
}

impl<'a> SessionPermit<'a> {
    fn for_worker(expected_epoch: u64, active_epoch: &'a AtomicU64) -> Self {
        Self {
            expected_epoch,
            active_epoch,
            #[cfg(test)]
            revoke_on_check: None,
            #[cfg(test)]
            check_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Return whether this request still belongs to the active session.
    #[must_use]
    pub(crate) fn is_current(&self) -> bool {
        #[cfg(test)]
        {
            let check = self.check_count.fetch_add(1, Ordering::SeqCst) + 1;
            if self.revoke_on_check == Some(check) {
                self.active_epoch
                    .store(self.expected_epoch.wrapping_add(1), Ordering::SeqCst);
            }
        }
        self.active_epoch.load(Ordering::SeqCst) == self.expected_epoch
    }

    #[cfg(test)]
    pub(crate) fn current_for_test(expected_epoch: u64, active_epoch: &'a AtomicU64) -> Self {
        Self::for_worker(expected_epoch, active_epoch)
    }

    #[cfg(test)]
    pub(crate) fn revoke_on_check(
        expected_epoch: u64,
        active_epoch: &'a AtomicU64,
        revoke_on_check: usize,
    ) -> Self {
        Self {
            expected_epoch,
            active_epoch,
            revoke_on_check: Some(revoke_on_check),
            check_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

/// Secret/network backend used by the standalone testnet demo.
///
/// Implementations must return only short, category-level Korean errors. They
/// must never place passwords, recovery phrases, keys, addresses, raw
/// transactions, RPC URLs, or raw server responses in an error string.
pub trait WalletBackend: Send + 'static {
    /// Generate a mnemonic wallet in memory and return its one-shot backup
    /// display. No vault may be written until verified confirmation succeeds.
    fn begin_generate_wallet(
        &mut self,
        words: NewMnemonicWords,
        password: SensitiveText,
        password_confirmation: SensitiveText,
    ) -> Result<GeneratedBackupReveal, String> {
        let _ = (words, password, password_confirmation);
        Err("지갑 관리 기능을 사용할 수 없습니다.".to_owned())
    }

    /// Consume the display stage and mint a random four-position prompt. The
    /// result contains positions and the original deadline only.
    fn begin_generated_backup_challenge(&mut self) -> Result<GeneratedBackupChallenge, String> {
        Err("생성 백업 확인 기능을 사용할 수 없습니다.".to_owned())
    }

    /// Consume exactly one response and persist only after backend verification
    /// and live permit checks at every irreversible boundary.
    fn confirm_generated_wallet(
        &mut self,
        confirmation: GeneratedBackupConfirmation,
        permit: &SessionPermit<'_>,
    ) -> Result<WalletSnapshot, String> {
        let _ = (confirmation, permit);
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

    /// Immediately revoke the unlocked in-memory session.
    ///
    /// This operation must be infallible and idempotent. Implementations must
    /// drop unlocked key material, an unconfirmed generated wallet, cached
    /// balances, and any prepared transfer. A durable signed pending-broadcast
    /// record must be preserved for exact retry after reauthentication.
    fn lock_wallet(&mut self);

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

    /// Add one full custom ERC-20 contract address to an unlocked v2 wallet.
    fn add_custom_token(
        &mut self,
        contract_address: &str,
    ) -> Result<Vec<CustomTokenSnapshot>, String> {
        let _ = contract_address;
        Err("커스텀 토큰 기능을 사용할 수 없습니다.".to_owned())
    }

    /// Revalidate every saved token against the pinned Sepolia endpoint.
    fn refresh_custom_tokens(&mut self) -> Result<Vec<CustomTokenSnapshot>, String> {
        Err("커스텀 토큰 기능을 사용할 수 없습니다.".to_owned())
    }

    /// Remove one exact saved contract from the authenticated v2 sidecar.
    fn remove_custom_token(
        &mut self,
        contract_address: &str,
    ) -> Result<Vec<CustomTokenSnapshot>, String> {
        let _ = contract_address;
        Err("커스텀 토큰 기능을 사용할 수 없습니다.".to_owned())
    }

    /// Validate inputs and freeze exact Sepolia transfer facts without signing.
    fn prepare_transfer(
        &mut self,
        recipient: &str,
        amount_eth: &str,
        fee_selection: FeeSelection,
    ) -> Result<TransferPreview, String>;

    /// Validate one authenticated saved token and freeze an exact ERC-20
    /// transfer without signing. UI-provided metadata is never accepted.
    fn prepare_saved_erc20_transfer(
        &mut self,
        contract_address: &str,
        recipient: &str,
        amount: &str,
        fee_selection: FeeSelection,
        permit: &SessionPermit<'_>,
    ) -> Result<Erc20TransferPreview, String> {
        let _ = (contract_address, recipient, amount, fee_selection, permit);
        Err("저장된 ERC-20 전송 기능을 사용할 수 없습니다.".to_owned())
    }

    /// Sign and submit only the currently prepared transfer while `permit`
    /// remains current at every irreversible boundary.
    fn confirm_prepared(&mut self, permit: &SessionPermit<'_>) -> Result<SendReceipt, String>;

    /// Invalidate the currently prepared transfer without signing.
    fn cancel_prepared(&mut self) -> Result<(), String>;

    /// Retry only the exact signed transaction durably retained after an
    /// ambiguous prior broadcast. This must never create a fresh signature.
    fn retry_pending(&mut self, permit: &SessionPermit<'_>) -> Result<SendReceipt, String>;
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
    Lock,
    BeginGenerate {
        words: NewMnemonicWords,
        password: SensitiveText,
        password_confirmation: SensitiveText,
    },
    BeginGeneratedBackupChallenge,
    ConfirmGenerated {
        confirmation: GeneratedBackupConfirmation,
    },
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
    AddCustomToken {
        contract_address: String,
    },
    RefreshCustomTokens,
    RemoveCustomToken {
        contract_address: String,
    },
    PrepareTransfer {
        recipient: String,
        amount_eth: String,
        fee_selection: FeeSelection,
    },
    PrepareSavedErc20Transfer {
        contract_address: String,
        recipient: String,
        amount: String,
        fee_selection: FeeSelection,
    },
    ConfirmPrepared,
    CancelPrepared,
    RetryPending,
}

enum WorkerEvent {
    Locked,
    GenerationBegun(Result<GeneratedBackupReveal, String>),
    GeneratedBackupChallengeBegun(Result<GeneratedBackupChallenge, String>),
    GeneratedConfirmed(Result<WalletSnapshot, String>),
    GeneratedCancelled(Result<(), String>),
    MnemonicImported(Result<WalletSnapshot, String>),
    PrivateKeyImported(Result<WalletSnapshot, String>),
    Opened(Result<WalletSnapshot, String>),
    LegacyMigrated(Result<WalletSnapshot, String>),
    MnemonicExported(Result<SecretReveal, String>),
    AccountPrivateKeyExported(Result<SecretReveal, String>),
    Refreshed(Result<WalletSnapshot, String>),
    CustomTokenAdded(Result<Vec<CustomTokenSnapshot>, String>),
    CustomTokensRefreshed(Result<Vec<CustomTokenSnapshot>, String>),
    CustomTokenRemoved(Result<Vec<CustomTokenSnapshot>, String>),
    TransferPrepared(Box<Result<TransferPreview, String>>),
    SavedErc20TransferPrepared(Box<Result<Erc20TransferPreview, String>>),
    PreparedConfirmed(Result<SendReceipt, String>),
    PreparedCancelled(Result<(), String>),
    Retried(Result<SendReceipt, String>),
}

/// Epoch-bound request sent to the single backend worker.
///
/// A lock publishes a new epoch before enqueuing its request. The worker drops
/// requests from older epochs without invoking their backend operation.
struct WorkerRequest {
    epoch: u64,
    command: WorkerCommand,
}

/// Epoch-bound result returned by the backend worker.
///
/// Dropping a stale response also drops and zeroizes any contained
/// `SecretReveal` before it can reach the UI reducer.
struct WorkerResponse {
    epoch: u64,
    event: WorkerEvent,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PendingAction {
    BeginGenerate,
    BeginGeneratedBackupChallenge,
    ConfirmGenerated,
    CancelGenerated,
    ImportMnemonic,
    ImportPrivateKey,
    Open,
    MigrateLegacy,
    ExportMnemonic,
    ExportAccountPrivateKey,
    Refresh,
    AddCustomToken,
    RefreshCustomTokens,
    RemoveCustomToken,
    PrepareTransfer,
    ConfirmPrepared,
    CancelPrepared,
    RetryPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LockReason {
    Explicit,
    Inactivity,
    FocusLost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionPhase {
    Locked,
    Locking(LockReason),
    Unlocked,
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum FeeMode {
    #[default]
    Recommended,
    Faster,
    Custom,
}

/// UI-only selection. A contract string is merely a request identifier; the
/// backend must reopen the authenticated sidecar and resolve it again.
#[derive(Clone, Default, Eq, PartialEq)]
enum TransferAssetChoice {
    #[default]
    Native,
    SavedErc20 {
        contract_address: String,
    },
}

#[derive(Clone, Eq, PartialEq)]
enum PreparedPreview {
    Native(TransferPreview),
    SavedErc20(Erc20TransferPreview),
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
    BeginGeneratedBackupChallenge,
    ConfirmGeneratedBackup,
    ExportMnemonic,
    ExportAccountPrivateKey,
}

struct TimedSecretReveal {
    reveal: SecretReveal,
    expires_at: Instant,
}

impl TimedSecretReveal {
    fn new(reveal: SecretReveal, now: Instant) -> Option<Self> {
        Some(Self {
            reveal,
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

enum GeneratedBackupUiState {
    Display(GeneratedBackupReveal),
    Challenge {
        challenge: GeneratedBackupChallenge,
        words: [Zeroizing<String>; GENERATED_BACKUP_CHALLENGE_WORDS],
        first_address: Zeroizing<String>,
    },
}

impl GeneratedBackupUiState {
    #[must_use]
    const fn expires_at(&self) -> Instant {
        match self {
            Self::Display(reveal) => reveal.expires_at(),
            Self::Challenge { challenge, .. } => challenge.expires_at(),
        }
    }

    #[must_use]
    fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at()
    }

    #[must_use]
    fn remaining_seconds(&self, now: Instant) -> u64 {
        self.expires_at().saturating_duration_since(now).as_secs()
    }
}

impl PendingAction {
    const fn korean(self) -> &'static str {
        match self {
            Self::BeginGeneratedBackupChallenge => "백업 확인 문제를 준비하는 중...",
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
            Self::AddCustomToken => "토큰 컨트랙트를 검증하고 저장하는 중...",
            Self::RefreshCustomTokens => "저장된 토큰을 Sepolia에서 다시 검증하는 중...",
            Self::RemoveCustomToken => "저장된 토큰을 제거하는 중...",
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
    commands: Option<Sender<WorkerRequest>>,
    events: Receiver<WorkerResponse>,
    active_epoch: Arc<AtomicU64>,
    session_epoch: u64,
    session_phase: SessionPhase,
    last_activity_at: Instant,
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
    custom_token_address: String,
    custom_tokens: Vec<CustomTokenSnapshot>,
    transfer_asset: TransferAssetChoice,
    recipient: String,
    amount_eth: String,
    fee_mode: FeeMode,
    custom_priority_fee_gwei: String,
    custom_max_fee_gwei: String,
    prepared: Option<PreparedPreview>,
    pending: Option<PendingAction>,
    hold: HoldToSend,
    secret_hold: HoldToSend,
    generated_backup: Option<GeneratedBackupUiState>,
    generated_backup_inputs_visible: bool,
    secret_reveal: Option<TimedSecretReveal>,
    secret_text_state_purge_pending: bool,
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
        let active_epoch = Arc::new(AtomicU64::new(0));
        spawn_worker(
            backend,
            command_receiver,
            event_sender,
            Arc::clone(&active_epoch),
        );
        Self {
            commands: Some(command_sender),
            events: event_receiver,
            active_epoch,
            session_epoch: 0,
            session_phase: SessionPhase::Locked,
            last_activity_at: Instant::now(),
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
            custom_token_address: String::new(),
            custom_tokens: Vec::new(),
            transfer_asset: TransferAssetChoice::Native,
            recipient: String::new(),
            amount_eth: String::new(),
            fee_mode: FeeMode::Recommended,
            custom_priority_fee_gwei: String::new(),
            custom_max_fee_gwei: String::new(),
            prepared: None,
            pending: None,
            hold: HoldToSend::default(),
            secret_hold: HoldToSend::default(),
            generated_backup: None,
            generated_backup_inputs_visible: false,
            secret_reveal: None,
            secret_text_state_purge_pending: false,
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
            active_epoch: Arc::new(AtomicU64::new(0)),
            session_epoch: 0,
            session_phase: SessionPhase::Locked,
            last_activity_at: Instant::now(),
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
            custom_token_address: String::new(),
            custom_tokens: Vec::new(),
            transfer_asset: TransferAssetChoice::Native,
            recipient: String::new(),
            amount_eth: String::new(),
            fee_mode: FeeMode::Recommended,
            custom_priority_fee_gwei: String::new(),
            custom_max_fee_gwei: String::new(),
            prepared: None,
            pending: None,
            hold: HoldToSend::default(),
            secret_hold: HoldToSend::default(),
            generated_backup: None,
            generated_backup_inputs_visible: false,
            secret_reveal: None,
            secret_text_state_purge_pending: false,
            notice: None,
            error: Some(safe_error(message.into())),
            last_transaction_hash: None,
        }
    }

    fn is_unlocked(&self) -> bool {
        self.session_phase == SessionPhase::Unlocked && self.snapshot.is_some()
    }

    fn require_unlocked_action(&mut self) -> bool {
        if self.is_unlocked() {
            true
        } else {
            self.error = Some("먼저 지갑을 다시 열어 주세요.".to_owned());
            false
        }
    }

    fn has_sensitive_session_state(&self) -> bool {
        self.session_phase != SessionPhase::Locked
            || self.pending.is_some()
            || self.snapshot.is_some()
            || self.prepared.is_some()
            || self.generated_backup.is_some()
            || self.secret_reveal.is_some()
            || !self.password.is_empty()
            || !self.password_confirmation.is_empty()
            || !self.old_password.is_empty()
            || !self.imported_secret.is_empty()
            || !self.reauth_password.is_empty()
    }

    fn generated_backup_ceremony_active(&self) -> bool {
        self.generated_backup.is_some()
            || matches!(
                self.pending,
                Some(
                    PendingAction::BeginGenerate
                        | PendingAction::BeginGeneratedBackupChallenge
                        | PendingAction::ConfirmGenerated
                        | PendingAction::CancelGenerated
                )
            )
    }

    fn purge_queued_secret_text_edit_state(&mut self, context: &egui::Context) {
        if std::mem::take(&mut self.secret_text_state_purge_pending) {
            purge_secret_text_edit_state(context);
        }
    }

    fn scrub_frontend_session(&mut self) {
        self.secret_text_state_purge_pending = true;
        self.password.zeroize();
        self.password_confirmation.zeroize();
        self.old_password.zeroize();
        self.imported_secret.zeroize();
        self.reauth_password.zeroize();
        self.custom_token_address.zeroize();
        self.recipient.zeroize();
        self.amount_eth.zeroize();
        self.custom_priority_fee_gwei.zeroize();
        self.custom_max_fee_gwei.zeroize();

        if let Some(snapshot) = self.snapshot.as_mut() {
            snapshot.address.zeroize();
            snapshot.balance_eth.zeroize();
        }
        self.snapshot = None;
        for token in &mut self.custom_tokens {
            token.contract_address.zeroize();
            match &mut token.state {
                CustomTokenState::Verified {
                    symbol, balance, ..
                } => {
                    if let Some(symbol) = symbol.as_mut() {
                        symbol.zeroize();
                    }
                    balance.zeroize();
                }
                CustomTokenState::Unavailable { reason_ko } => reason_ko.zeroize(),
            }
        }
        self.custom_tokens.clear();
        zeroize_transfer_asset_choice(&mut self.transfer_asset);
        self.transfer_asset = TransferAssetChoice::Native;
        if let Some(preview) = self.prepared.as_mut() {
            zeroize_prepared_preview(preview);
        }
        self.prepared = None;
        self.pending = None;
        self.generated_backup = None;
        self.generated_backup_inputs_visible = false;
        self.secret_reveal = None;
        zeroize_optional_string(&mut self.notice);
        zeroize_optional_string(&mut self.error);
        zeroize_optional_string(&mut self.last_transaction_hash);

        self.password_visible = false;
        self.imported_secret_visible = false;
        self.setup_mode = SetupMode::Open;
        self.export_kind = SecretRevealKind::Mnemonic;
        self.fee_mode = FeeMode::Recommended;
        self.hold.reset();
        self.secret_hold.reset();
    }

    fn request_lock(&mut self, reason: LockReason) {
        if matches!(self.session_phase, SessionPhase::Locking(_)) {
            return;
        }
        let Some(next_epoch) = self.session_epoch.checked_add(1) else {
            self.active_epoch.store(u64::MAX, Ordering::SeqCst);
            self.scrub_frontend_session();
            self.commands = None;
            self.session_phase = SessionPhase::Locked;
            self.error =
                Some("잠금 세션을 안전하게 갱신할 수 없어 지갑을 사용할 수 없습니다.".to_owned());
            return;
        };

        self.session_epoch = next_epoch;
        self.active_epoch.store(next_epoch, Ordering::SeqCst);
        self.scrub_frontend_session();
        self.session_phase = SessionPhase::Locking(reason);

        let accepted = self.commands.as_ref().is_some_and(|sender| {
            sender
                .send(WorkerRequest {
                    epoch: next_epoch,
                    command: WorkerCommand::Lock,
                })
                .is_ok()
        });
        if !accepted {
            self.commands = None;
            self.session_phase = SessionPhase::Locked;
            self.error = Some("잠금 작업 스레드가 종료되어 지갑을 다시 열 수 없습니다.".to_owned());
        }
    }

    fn observe_automatic_lock(&mut self, context: &egui::Context, now: Instant) {
        let (focused, user_activity) = context.input(|input| {
            (
                input.focused,
                input.events.iter().any(is_user_activity_event),
            )
        });
        if focused && user_activity {
            self.last_activity_at = now;
        }

        let sensitive = self.has_sensitive_session_state();
        if let Some(reason) = automatic_lock_reason(
            sensitive,
            self.session_phase,
            self.last_activity_at,
            now,
            focused,
        ) {
            self.request_lock(reason);
            return;
        }
        if sensitive && focused {
            let remaining = INACTIVITY_LOCK_DURATION
                .saturating_sub(now.saturating_duration_since(self.last_activity_at));
            context.request_repaint_after(remaining.min(Duration::from_secs(1)));
        }
    }

    fn send_command(&mut self, command: WorkerCommand, action: PendingAction) {
        if matches!(
            action,
            PendingAction::BeginGenerate
                | PendingAction::BeginGeneratedBackupChallenge
                | PendingAction::ConfirmGenerated
                | PendingAction::CancelGenerated
                | PendingAction::ImportMnemonic
                | PendingAction::ImportPrivateKey
                | PendingAction::Open
                | PendingAction::MigrateLegacy
                | PendingAction::ExportMnemonic
                | PendingAction::ExportAccountPrivateKey
        ) {
            self.secret_text_state_purge_pending = true;
        }
        self.error = None;
        self.notice = None;
        if matches!(self.session_phase, SessionPhase::Locking(_)) {
            self.error = Some("지갑을 잠그는 중입니다.".to_owned());
            return;
        }
        let accepted = self.commands.as_ref().is_some_and(|sender| {
            sender
                .send(WorkerRequest {
                    epoch: self.session_epoch,
                    command,
                })
                .is_ok()
        });
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

    fn begin_generated_backup_challenge(&mut self) {
        let Some(GeneratedBackupUiState::Display(reveal)) = self.generated_backup.take() else {
            return;
        };
        // Drop and zeroize the full phrase and displayed address before asking
        // the worker to mint the challenge metadata.
        drop(reveal);
        self.generated_backup_inputs_visible = false;
        self.secret_hold.reset();
        self.send_command(
            WorkerCommand::BeginGeneratedBackupChallenge,
            PendingAction::BeginGeneratedBackupChallenge,
        );
    }

    fn confirm_generated_wallet(&mut self) {
        let Some(GeneratedBackupUiState::Challenge {
            challenge: _,
            words,
            first_address,
        }) = self.generated_backup.take()
        else {
            return;
        };
        self.generated_backup_inputs_visible = false;
        let confirmation = GeneratedBackupConfirmation::new(
            words.map(|mut word| SensitiveText::new(std::mem::take(&mut *word))),
            SensitiveText::new({
                let mut first_address = first_address;
                std::mem::take(&mut *first_address)
            }),
        );
        self.secret_hold.reset();
        self.send_command(
            WorkerCommand::ConfirmGenerated { confirmation },
            PendingAction::ConfirmGenerated,
        );
    }

    fn cancel_generated_wallet(&mut self) {
        self.generated_backup = None;
        self.generated_backup_inputs_visible = false;
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
        if !self.require_unlocked_action() {
            self.secret_hold.reset();
            return;
        }
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
            SecretHoldAction::BeginGeneratedBackupChallenge
            | SecretHoldAction::ConfirmGeneratedBackup => return,
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
            SecretHoldAction::BeginGeneratedBackupChallenge => {
                let valid_backup = self.generated_backup.as_ref().is_some_and(|state| {
                    matches!(state, GeneratedBackupUiState::Display(_))
                        && !state.is_expired(Instant::now())
                });
                if !valid_backup {
                    return false;
                }
                self.begin_generated_backup_challenge();
                self.pending == Some(PendingAction::BeginGeneratedBackupChallenge)
            }
            SecretHoldAction::ConfirmGeneratedBackup => {
                let valid_confirmation = self.generated_backup.as_ref().is_some_and(|state| {
                    let GeneratedBackupUiState::Challenge {
                        words,
                        first_address,
                        ..
                    } = state
                    else {
                        return false;
                    };
                    !state.is_expired(Instant::now())
                        && words
                            .iter()
                            .all(|word| valid_backup_word_shape(word.as_str()))
                        && valid_backup_address_shape(first_address.as_str())
                });
                if !valid_confirmation {
                    return false;
                }
                self.confirm_generated_wallet();
                self.pending == Some(PendingAction::ConfirmGenerated)
            }
            SecretHoldAction::ExportMnemonic | SecretHoldAction::ExportAccountPrivateKey => {
                if self.prepared.is_some()
                    || self.generated_backup.is_some()
                    || self.secret_reveal.is_some()
                {
                    return false;
                }
                self.export_secret(action);
                self.pending.is_some()
            }
        }
    }

    fn expire_secret_reveal(&mut self, now: Instant) {
        let expired = self
            .secret_reveal
            .as_ref()
            .is_some_and(|reveal| reveal.is_expired(now));
        if expired {
            self.secret_reveal = None;
            self.secret_hold.reset();
            self.notice = Some("비밀값 표시 시간이 끝나 메모리에서 지웠습니다.".to_owned());
        }
    }

    fn expire_generated_backup(&mut self, now: Instant) {
        let expired = self
            .generated_backup
            .as_ref()
            .is_some_and(|state| state.is_expired(now));
        if expired {
            self.generated_backup = None;
            self.generated_backup_inputs_visible = false;
            self.secret_hold.reset();
            if self.pending.is_none() {
                self.send_command(
                    WorkerCommand::CancelGenerated,
                    PendingAction::CancelGenerated,
                );
            }
        }
    }

    fn refresh(&mut self) {
        if !self.require_unlocked_action() {
            return;
        }
        self.send_command(WorkerCommand::Refresh, PendingAction::Refresh);
    }

    fn add_custom_token(&mut self) {
        if !self.require_unlocked_action() {
            return;
        }
        let contract_address = self.custom_token_address.trim().to_owned();
        if !valid_recipient_shape(&contract_address) {
            self.error = Some("토큰 컨트랙트 주소 형식을 확인해 주세요.".to_owned());
            return;
        }
        self.send_command(
            WorkerCommand::AddCustomToken { contract_address },
            PendingAction::AddCustomToken,
        );
    }

    fn refresh_custom_tokens(&mut self) {
        if !self.require_unlocked_action() {
            return;
        }
        self.send_command(
            WorkerCommand::RefreshCustomTokens,
            PendingAction::RefreshCustomTokens,
        );
    }

    fn remove_custom_token(&mut self, contract_address: String) {
        if !self.require_unlocked_action() {
            return;
        }
        self.send_command(
            WorkerCommand::RemoveCustomToken { contract_address },
            PendingAction::RemoveCustomToken,
        );
    }

    fn prepare_transfer(&mut self) {
        if !self.require_unlocked_action() {
            self.hold.reset();
            return;
        }
        let recipient = self.recipient.trim().to_owned();
        let amount = self.amount_eth.trim().to_owned();
        let fee_selection = match self.fee_mode {
            FeeMode::Recommended => FeeSelection::Recommended,
            FeeMode::Faster => FeeSelection::Faster,
            FeeMode::Custom => FeeSelection::Custom {
                max_priority_fee_per_gas_gwei: self.custom_priority_fee_gwei.clone(),
                max_fee_per_gas_gwei: self.custom_max_fee_gwei.clone(),
            },
        };
        self.hold.reset();
        match self.transfer_asset.clone() {
            TransferAssetChoice::Native => self.send_command(
                WorkerCommand::PrepareTransfer {
                    recipient,
                    amount_eth: amount,
                    fee_selection,
                },
                PendingAction::PrepareTransfer,
            ),
            TransferAssetChoice::SavedErc20 { contract_address } => {
                if verified_token_by_contract(&self.custom_tokens, &contract_address).is_none() {
                    zeroize_custom_token_snapshots(&mut self.custom_tokens);
                    reset_transfer_selection_after_token_change(
                        &mut self.transfer_asset,
                        &mut self.prepared,
                        &mut self.hold,
                        &mut self.amount_eth,
                        &mut self.secret_text_state_purge_pending,
                    );
                    self.error =
                        Some("저장된 토큰을 다시 검증한 뒤 전송 자산을 선택해 주세요.".to_owned());
                    return;
                }
                self.send_command(
                    WorkerCommand::PrepareSavedErc20Transfer {
                        contract_address,
                        recipient,
                        amount,
                        fee_selection,
                    },
                    PendingAction::PrepareTransfer,
                );
            }
        }
    }

    fn confirm_prepared(&mut self) {
        if !self.require_unlocked_action() {
            self.hold.reset();
            return;
        }
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
        if !self.require_unlocked_action() {
            self.hold.reset();
            return;
        }
        if self.prepared.is_none() {
            return;
        }
        self.hold.reset();
        self.send_command(WorkerCommand::CancelPrepared, PendingAction::CancelPrepared);
    }

    fn retry_pending(&mut self) {
        if !self.require_unlocked_action() {
            self.hold.reset();
            return;
        }
        self.hold.reset();
        self.send_command(WorkerCommand::RetryPending, PendingAction::RetryPending);
    }

    fn process_events(&mut self) {
        loop {
            let response = match self.events.try_recv() {
                Ok(response) => response,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if self.commands.is_some()
                        && (self.pending.is_some()
                            || matches!(self.session_phase, SessionPhase::Locking(_)))
                    {
                        self.pending = None;
                        self.commands = None;
                        self.scrub_frontend_session();
                        self.session_phase = SessionPhase::Locked;
                        self.error = Some(
                            "지갑 백엔드가 중단되었습니다. 앱을 다시 실행해 주세요.".to_owned(),
                        );
                    }
                    break;
                }
            };
            if response.epoch != self.session_epoch {
                self.secret_text_state_purge_pending = true;
                drop(response);
                continue;
            }
            self.apply_worker_event(response.event);
        }
    }

    fn apply_worker_event(&mut self, event: WorkerEvent) {
        self.pending = None;
        if matches!(
            &event,
            WorkerEvent::GenerationBegun(_)
                | WorkerEvent::GeneratedBackupChallengeBegun(_)
                | WorkerEvent::GeneratedConfirmed(_)
                | WorkerEvent::GeneratedCancelled(_)
        ) {
            self.secret_text_state_purge_pending = true;
        }
        match event {
            WorkerEvent::Locked => {
                let reason = match self.session_phase {
                    SessionPhase::Locking(reason) => reason,
                    SessionPhase::Locked | SessionPhase::Unlocked => LockReason::Explicit,
                };
                self.scrub_frontend_session();
                self.session_phase = SessionPhase::Locked;
                self.last_activity_at = Instant::now();
                self.notice = Some(lock_notice(reason).to_owned());
            }
            WorkerEvent::GenerationBegun(result) => match result {
                Ok(reveal) => {
                    self.generated_backup_inputs_visible = false;
                    self.generated_backup = Some(GeneratedBackupUiState::Display(reveal));
                    self.secret_hold.reset();
                    self.notice = Some(
                        "복구 문구는 아직 저장되지 않았습니다. 적어 둔 뒤 2초 확인을 완료하세요."
                            .to_owned(),
                    );
                }
                Err(error) => self.error = Some(safe_error(error)),
            },
            WorkerEvent::GeneratedBackupChallengeBegun(result) => match result {
                Ok(challenge) if Instant::now() < challenge.expires_at() => {
                    self.generated_backup_inputs_visible = false;
                    self.generated_backup = Some(GeneratedBackupUiState::Challenge {
                        challenge,
                        words: std::array::from_fn(|_| Zeroizing::new(String::new())),
                        first_address: Zeroizing::new(String::new()),
                    });
                    self.notice = Some(
                        "지정된 네 단어와 첫 번째 전체 주소를 직접 입력해 확인하세요.".to_owned(),
                    );
                }
                Ok(_) => {
                    self.generated_backup = None;
                    self.generated_backup_inputs_visible = false;
                    self.send_command(
                        WorkerCommand::CancelGenerated,
                        PendingAction::CancelGenerated,
                    );
                }
                Err(error) => {
                    self.generated_backup = None;
                    self.generated_backup_inputs_visible = false;
                    self.error = Some(safe_error(error));
                }
            },
            WorkerEvent::GeneratedConfirmed(result) => match result {
                Ok(snapshot) => {
                    clear_prepared_state(&mut self.prepared, &mut self.hold);
                    self.generated_backup = None;
                    self.generated_backup_inputs_visible = false;
                    self.custom_tokens.clear();
                    self.snapshot = Some(snapshot);
                    self.session_phase = SessionPhase::Unlocked;
                    self.last_activity_at = Instant::now();
                    self.notice = Some(
                        "복구 문구 백업을 확인하고 새 v2 테스트 지갑을 저장했습니다.".to_owned(),
                    );
                }
                Err(error) => self.error = Some(safe_error(error)),
            },
            WorkerEvent::GeneratedCancelled(result) => match result {
                Ok(()) => {
                    self.generated_backup = None;
                    self.generated_backup_inputs_visible = false;
                    if self.snapshot.is_none() {
                        self.session_phase = SessionPhase::Locked;
                    }
                    self.notice =
                        Some("저장하지 않은 복구 문구를 메모리에서 지웠습니다.".to_owned());
                }
                Err(error) => self.error = Some(safe_error(error)),
            },
            WorkerEvent::MnemonicImported(result) | WorkerEvent::PrivateKeyImported(result) => {
                match result {
                    Ok(snapshot) => {
                        clear_prepared_state(&mut self.prepared, &mut self.hold);
                        self.custom_tokens.clear();
                        self.snapshot = Some(snapshot);
                        self.session_phase = SessionPhase::Unlocked;
                        self.last_activity_at = Instant::now();
                        self.notice =
                            Some("가져온 비밀값을 v2 테스트 지갑으로 저장했습니다.".to_owned());
                    }
                    Err(error) => self.error = Some(safe_error(error)),
                }
            }
            WorkerEvent::Opened(result) => match result {
                Ok(snapshot) => {
                    let load_custom_tokens =
                        !matches!(snapshot.wallet_kind, WalletKind::LegacyV1RawPrivateKey);
                    clear_prepared_state(&mut self.prepared, &mut self.hold);
                    self.custom_tokens.clear();
                    self.snapshot = Some(snapshot);
                    self.session_phase = SessionPhase::Unlocked;
                    self.last_activity_at = Instant::now();
                    if load_custom_tokens {
                        self.send_command(
                            WorkerCommand::RefreshCustomTokens,
                            PendingAction::RefreshCustomTokens,
                        );
                    } else {
                        self.notice = Some("테스트 지갑을 열었습니다.".to_owned());
                    }
                }
                Err(error) => {
                    clear_prepared_state(&mut self.prepared, &mut self.hold);
                    self.secret_reveal = None;
                    self.custom_tokens.clear();
                    self.snapshot = None;
                    self.session_phase = SessionPhase::Locked;
                    self.error = Some(safe_error(error));
                }
            },
            WorkerEvent::LegacyMigrated(result) => match result {
                Ok(snapshot) => {
                    clear_prepared_state(&mut self.prepared, &mut self.hold);
                    self.custom_tokens.clear();
                    self.snapshot = Some(snapshot);
                    self.session_phase = SessionPhase::Unlocked;
                    self.last_activity_at = Instant::now();
                    self.notice = Some(
                        "계정 주소를 유지한 채 v1 개인 키 지갑을 v2로 이전했습니다.".to_owned(),
                    );
                }
                Err(error) => {
                    clear_prepared_state(&mut self.prepared, &mut self.hold);
                    self.secret_reveal = None;
                    self.custom_tokens.clear();
                    self.snapshot = None;
                    self.session_phase = SessionPhase::Locked;
                    self.error = Some(safe_error(error));
                }
            },
            WorkerEvent::MnemonicExported(result)
            | WorkerEvent::AccountPrivateKeyExported(result) => match result {
                Ok(reveal) => {
                    clear_prepared_state(&mut self.prepared, &mut self.hold);
                    self.secret_reveal = TimedSecretReveal::new(reveal, Instant::now());
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
            WorkerEvent::CustomTokenAdded(result) => match result {
                Ok(tokens) => {
                    self.custom_tokens = sanitize_custom_tokens(tokens);
                    reset_transfer_selection_after_token_change(
                        &mut self.transfer_asset,
                        &mut self.prepared,
                        &mut self.hold,
                        &mut self.amount_eth,
                        &mut self.secret_text_state_purge_pending,
                    );
                    self.custom_token_address.clear();
                    self.notice =
                        Some("커스텀 토큰을 검증하고 암호화 목록에 저장했습니다.".to_owned());
                }
                Err(error) => {
                    self.custom_tokens.clear();
                    reset_transfer_selection_after_token_change(
                        &mut self.transfer_asset,
                        &mut self.prepared,
                        &mut self.hold,
                        &mut self.amount_eth,
                        &mut self.secret_text_state_purge_pending,
                    );
                    self.error = Some(safe_error(error));
                }
            },
            WorkerEvent::CustomTokensRefreshed(result) => match result {
                Ok(tokens) => {
                    self.custom_tokens = sanitize_custom_tokens(tokens);
                    reset_transfer_selection_after_token_change(
                        &mut self.transfer_asset,
                        &mut self.prepared,
                        &mut self.hold,
                        &mut self.amount_eth,
                        &mut self.secret_text_state_purge_pending,
                    );
                    self.notice = Some("저장된 커스텀 토큰을 다시 검증했습니다.".to_owned());
                }
                Err(error) => {
                    self.custom_tokens.clear();
                    reset_transfer_selection_after_token_change(
                        &mut self.transfer_asset,
                        &mut self.prepared,
                        &mut self.hold,
                        &mut self.amount_eth,
                        &mut self.secret_text_state_purge_pending,
                    );
                    self.error = Some(safe_error(error));
                }
            },
            WorkerEvent::CustomTokenRemoved(result) => match result {
                Ok(tokens) => {
                    self.custom_tokens = sanitize_custom_tokens(tokens);
                    reset_transfer_selection_after_token_change(
                        &mut self.transfer_asset,
                        &mut self.prepared,
                        &mut self.hold,
                        &mut self.amount_eth,
                        &mut self.secret_text_state_purge_pending,
                    );
                    self.notice = Some("커스텀 토큰을 암호화 목록에서 제거했습니다.".to_owned());
                }
                Err(error) => {
                    self.custom_tokens.clear();
                    reset_transfer_selection_after_token_change(
                        &mut self.transfer_asset,
                        &mut self.prepared,
                        &mut self.hold,
                        &mut self.amount_eth,
                        &mut self.secret_text_state_purge_pending,
                    );
                    self.error = Some(safe_error(error));
                }
            },
            WorkerEvent::TransferPrepared(result) => match *result {
                Ok(preview) => {
                    self.prepared = Some(PreparedPreview::Native(preview));
                    self.notice = None;
                    self.error = None;
                    self.hold.reset();
                }
                Err(error) => {
                    self.prepared = None;
                    self.error = Some(safe_error(error));
                }
            },
            WorkerEvent::SavedErc20TransferPrepared(result) => match *result {
                Ok(preview) => {
                    self.prepared = Some(PreparedPreview::SavedErc20(preview));
                    self.notice = None;
                    self.error = None;
                    self.hold.reset();
                }
                Err(error) => {
                    zeroize_custom_token_snapshots(&mut self.custom_tokens);
                    reset_transfer_selection_after_token_change(
                        &mut self.transfer_asset,
                        &mut self.prepared,
                        &mut self.hold,
                        &mut self.amount_eth,
                        &mut self.secret_text_state_purge_pending,
                    );
                    self.error = Some(safe_error(error));
                }
            },
            WorkerEvent::PreparedConfirmed(result) => match result {
                Ok(receipt) => {
                    let was_erc20 = matches!(self.prepared, Some(PreparedPreview::SavedErc20(_)));
                    clear_prepared_state(&mut self.prepared, &mut self.hold);
                    zeroize_transfer_asset_choice(&mut self.transfer_asset);
                    self.transfer_asset = TransferAssetChoice::Native;
                    self.last_transaction_hash = Some(receipt.transaction_hash);
                    self.recipient.zeroize();
                    self.amount_eth.zeroize();
                    self.secret_text_state_purge_pending = true;
                    mark_snapshot_balance_stale(self.snapshot.as_mut());
                    if was_erc20 {
                        zeroize_custom_token_snapshots(&mut self.custom_tokens);
                    }
                    self.notice = Some(
                        "Sepolia 테스트 전송을 제출했습니다. 반영까지 잠시 걸릴 수 있습니다."
                            .to_owned(),
                    );
                }
                Err(error) => {
                    let was_erc20 = matches!(self.prepared, Some(PreparedPreview::SavedErc20(_)));
                    mark_snapshot_balance_stale(self.snapshot.as_mut());
                    if was_erc20 {
                        zeroize_custom_token_snapshots(&mut self.custom_tokens);
                        reset_transfer_selection_after_token_change(
                            &mut self.transfer_asset,
                            &mut self.prepared,
                            &mut self.hold,
                            &mut self.amount_eth,
                            &mut self.secret_text_state_purge_pending,
                        );
                    } else {
                        clear_prepared_state(&mut self.prepared, &mut self.hold);
                    }
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
                    mark_snapshot_balance_stale(self.snapshot.as_mut());
                    zeroize_custom_token_snapshots(&mut self.custom_tokens);
                    self.notice =
                        Some("저장된 이전 Sepolia 거래를 그대로 다시 제출했습니다. 잔액을 다시 조회해 주세요.".to_owned());
                }
                Err(error) => {
                    mark_snapshot_balance_stale(self.snapshot.as_mut());
                    zeroize_custom_token_snapshots(&mut self.custom_tokens);
                    reset_transfer_selection_after_token_change(
                        &mut self.transfer_asset,
                        &mut self.prepared,
                        &mut self.hold,
                        &mut self.amount_eth,
                        &mut self.secret_text_state_purge_pending,
                    );
                    self.error = Some(safe_error(error));
                }
            },
        }
    }

    fn session_controls(&mut self, ui: &mut egui::Ui) -> bool {
        match self.session_phase {
            SessionPhase::Locking(_) => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.strong("지갑의 메모리 세션을 잠그는 중입니다…");
                });
                true
            }
            SessionPhase::Unlocked => {
                let clicked = ui.button("지갑 잠그기").clicked();
                if clicked {
                    self.request_lock(LockReason::Explicit);
                }
                clicked
            }
            SessionPhase::Locked if self.has_sensitive_session_state() => {
                let clicked = ui.button("민감한 입력을 지우고 잠그기").clicked();
                if clicked {
                    self.request_lock(LockReason::Explicit);
                }
                clicked
            }
            SessionPhase::Locked => false,
        }
    }

    fn wallet_setup(&mut self, ui: &mut egui::Ui) {
        let setup_enabled = self.session_phase == SessionPhase::Locked
            && self.commands.is_some()
            && self.pending.is_none()
            && self.prepared.is_none()
            && self.generated_backup.is_none();
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
                .id(imported_secret_text_edit_id())
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
                .id(old_password_text_edit_id())
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
                .id(password_text_edit_id())
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
                .id(password_confirmation_text_edit_id())
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
                .id(reauth_password_text_edit_id())
                .hint_text("현재 비밀번호 재입력")
                .desired_width(320.0)
                .password(true);
            let enabled = self.pending.is_none()
                && self.prepared.is_none()
                && self.generated_backup.is_none()
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
                SecretHoldAction::BeginGeneratedBackupChallenge
                | SecretHoldAction::ConfirmGeneratedBackup => unreachable!(),
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

    fn generated_backup_panel(&mut self, context: &egui::Context, ui: &mut egui::Ui) {
        let Some(state) = self.generated_backup.as_mut() else {
            return;
        };
        let now = Instant::now();
        let remaining = state.remaining_seconds(now);
        let live = !state.is_expired(now);
        let palette = StatusPalette::from_visuals(ui.visuals());
        let mut cancel = false;
        let mut begin_outcome = None;
        let mut confirm_outcome = None;

        ui.separator();
        ui.heading("생성 지갑 백업 확인");
        ui.colored_label(
            palette.warning,
            format!("백엔드 확인 제한 시간: {remaining}초 남음"),
        );
        match state {
            GeneratedBackupUiState::Display(reveal) => {
                ui.strong("1단계: 복구 구문과 첫 번째 주소를 별도 매체에 기록하세요.");
                egui::Grid::new("generated-backup-numbered-words")
                    .num_columns(6)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        for (index, word) in numbered_backup_words(reveal.phrase()) {
                            ui.label(RichText::new(format!("{index:>2}.")).monospace());
                            let _ = ui.add(
                                egui::Label::new(RichText::new(word).monospace().size(18.0))
                                    .selectable(false),
                            );
                            if index % 3 == 0 {
                                ui.end_row();
                            }
                        }
                    });
                ui.label("첫 번째 파생 주소 (m/44'/60'/0'/0/0)");
                let _ = ui.add(
                    egui::Label::new(RichText::new(reveal.first_address()).monospace())
                        .selectable(false)
                        .wrap(),
                );
                ui.label(
                    RichText::new("복사하지 말고 오프라인 백업에서 다시 읽어 입력해야 합니다.")
                        .small()
                        .color(palette.muted),
                );
                ui.horizontal(|ui| {
                    cancel = ui
                        .add_enabled(
                            self.pending.is_none(),
                            egui::Button::new("생성을 취소하고 지우기"),
                        )
                        .clicked();
                    let enabled = self.pending.is_none() && live;
                    let response = ui.add_enabled(
                        enabled,
                        secret_hold_button("기록 완료: 문제 단계로 이동 (2초 누르기)"),
                    );
                    begin_outcome = Some(
                        self.secret_hold
                            .update(now, hold_to_send_input(context, &response, enabled)),
                    );
                });
                let progress = self.secret_hold.fraction(now);
                let _ = ui.add(
                    egui::ProgressBar::new(progress)
                        .desired_width(300.0)
                        .text(format!("{:.1} / 2.0초", progress * 2.0)),
                );
            }
            GeneratedBackupUiState::Challenge {
                challenge,
                words,
                first_address,
            } => {
                ui.checkbox(&mut self.generated_backup_inputs_visible, "입력 내용 표시");
                ui.strong("2단계: 오프라인 백업만 보고 네 단어와 전체 주소를 입력하세요.");
                let positions = challenge.positions();
                for (index, (position, word)) in
                    positions.into_iter().zip(words.iter_mut()).enumerate()
                {
                    ui.horizontal(|ui| {
                        ui.label(format!("{position}번째 단어"));
                        let _ = ui.add_enabled(
                            self.pending.is_none(),
                            egui::TextEdit::singleline(&mut **word)
                                .id(generated_backup_word_text_edit_id(index))
                                .password(!self.generated_backup_inputs_visible)
                                .char_limit(8)
                                .desired_width(220.0),
                        );
                    });
                }
                ui.label("첫 번째 파생 주소 전체");
                let _ = ui.add_enabled(
                    self.pending.is_none(),
                    egui::TextEdit::singleline(&mut **first_address)
                        .id(generated_backup_address_text_edit_id())
                        .char_limit(42)
                        .desired_width(500.0),
                );
                ui.label(
                    RichText::new(
                        "한 번이라도 일치하지 않으면 이 생성 시도는 폐기되며 파일을 만들지 않습니다.",
                    )
                    .small()
                    .color(palette.muted),
                );
                ui.colored_label(palette.warning, GENERATED_BACKUP_ONE_ATTEMPT_WARNING);
                let ready = words
                    .iter()
                    .all(|word| valid_backup_word_shape(word.as_str()))
                    && valid_backup_address_shape(first_address.as_str());
                ui.horizontal(|ui| {
                    cancel = ui
                        .add_enabled(
                            self.pending.is_none(),
                            egui::Button::new("생성을 취소하고 지우기"),
                        )
                        .clicked();
                    let confirm_enabled = self.pending.is_none() && live && ready;
                    let response = ui.add_enabled(
                        confirm_enabled,
                        secret_hold_button("백업 확인 후 v2 지갑 저장 — 2초 누르기"),
                    );
                    confirm_outcome = Some(
                        self.secret_hold
                            .update(now, hold_to_send_input(context, &response, confirm_enabled)),
                    );
                });
                let progress = self.secret_hold.fraction(now);
                let _ = ui.add(
                    egui::ProgressBar::new(progress)
                        .desired_width(300.0)
                        .text(format!("{:.1} / 2.0초", progress * 2.0)),
                );
            }
        }

        if cancel {
            self.cancel_generated_wallet();
        } else if let Some(outcome) = begin_outcome {
            let _ = self.handle_secret_hold_outcome(
                outcome,
                SecretHoldAction::BeginGeneratedBackupChallenge,
            );
            if matches!(outcome, HoldOutcome::Holding(_)) {
                context.request_repaint_after(Duration::from_millis(16));
            }
        } else if let Some(outcome) = confirm_outcome {
            let _ =
                self.handle_secret_hold_outcome(outcome, SecretHoldAction::ConfirmGeneratedBackup);
            if matches!(outcome, HoldOutcome::Holding(_)) {
                context.request_repaint_after(Duration::from_millis(16));
            }
        }
        context.request_repaint_after(Duration::from_millis(100));
    }

    fn secret_reveal_panel(&mut self, context: &egui::Context, ui: &mut egui::Ui) {
        let Some(reveal) = self.secret_reveal.as_ref() else {
            return;
        };
        let now = Instant::now();
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
        if ui.button("지금 지우기").clicked() {
            self.secret_reveal = None;
            self.secret_hold.reset();
        }
        context.request_repaint_after(Duration::from_millis(100));
    }

    fn custom_token_panel(&mut self, ui: &mut egui::Ui) {
        let Some(snapshot) = self.snapshot.as_ref() else {
            return;
        };
        let palette = StatusPalette::from_visuals(ui.visuals());
        ui.separator();
        ui.heading("3. 커스텀 ERC-20 토큰");
        if matches!(snapshot.wallet_kind, WalletKind::LegacyV1RawPrivateKey) {
            ui.colored_label(
                palette.warning,
                "커스텀 토큰 목록은 v2 지갑에서만 사용할 수 있습니다. 먼저 v1 → v2 이전을 완료하세요.",
            );
            return;
        }

        ui.label(
            "Sepolia 토큰 컨트랙트의 전체 주소를 추가합니다. 저장된 메타데이터는 매 조회 때 온체인 코드와 다시 대조합니다.",
        );
        let mutation_enabled =
            self.pending.is_none() && self.prepared.is_none() && self.secret_reveal.is_none();
        ui.horizontal(|ui| {
            let _ = ui.add_enabled(
                mutation_enabled,
                egui::TextEdit::singleline(&mut self.custom_token_address)
                    .id(custom_token_address_text_edit_id())
                    .hint_text("0x로 시작하는 토큰 컨트랙트 주소")
                    .desired_width(500.0),
            );
            if ui
                .add_enabled(
                    mutation_enabled && valid_recipient_shape(self.custom_token_address.trim()),
                    egui::Button::new("검증 후 추가"),
                )
                .clicked()
            {
                self.add_custom_token();
            }
        });
        if !self.custom_token_address.trim().is_empty()
            && !valid_recipient_shape(self.custom_token_address.trim())
        {
            ui.colored_label(palette.error, "토큰 컨트랙트 주소 형식을 확인해 주세요.");
        }
        ui.horizontal(|ui| {
            if ui
                .add_enabled(mutation_enabled, egui::Button::new("저장된 토큰 다시 검증"))
                .clicked()
            {
                self.refresh_custom_tokens();
            }
            ui.label(
                RichText::new(
                    "최대 32개 · 저장 후 다시 검증된 ERC-20만 전송 자산으로 선택할 수 있습니다.",
                )
                .small()
                .color(palette.muted),
            );
        });

        if self.custom_tokens.is_empty() {
            ui.label(
                RichText::new("저장된 커스텀 토큰이 없습니다.")
                    .small()
                    .color(palette.muted),
            );
            return;
        }

        for token in self.custom_tokens.clone() {
            ui.add_space(6.0);
            ui.group(|ui| {
                ui.label(RichText::new("컨트랙트 주소").strong());
                ui.label(RichText::new(&token.contract_address).monospace());
                match &token.state {
                    CustomTokenState::Verified {
                        symbol,
                        decimals,
                        balance,
                    } => {
                        let display_symbol = symbol.as_deref().unwrap_or("심볼 없음");
                        ui.label(format!("컨트랙트 제공 심볼: {display_symbol}"));
                        ui.label(format!("decimals: {decimals}"));
                        ui.label(format!("계정 0 잔액: {balance}"));
                    }
                    CustomTokenState::Unavailable { reason_ko } => {
                        ui.colored_label(palette.error, reason_ko);
                        ui.label(
                            RichText::new(
                                "검증에 실패해 저장된 심볼·decimals·잔액을 표시하지 않습니다.",
                            )
                            .small()
                            .color(palette.muted),
                        );
                    }
                }
                if ui
                    .add_enabled(mutation_enabled, egui::Button::new("목록에서 제거"))
                    .clicked()
                {
                    self.remove_custom_token(token.contract_address.clone());
                }
            });
        }
        ui.label(
            RichText::new(
                "토큰 목록 generation은 롤백 방지 앵커가 아닙니다. 과거의 유효한 목록 파일을 복원하면 제거했던 토큰이 다시 나타날 수 있으므로 전체 주소와 재검증 결과를 확인하세요.",
            )
            .small()
            .color(palette.muted),
        );
    }

    fn send_panel(&mut self, context: &egui::Context, ui: &mut egui::Ui) {
        if self.snapshot.is_none() {
            return;
        }
        let palette = StatusPalette::from_visuals(ui.visuals());
        ui.separator();
        ui.heading("4. 테스트 자산 보내기");
        let preparing_allowed = self.prepared.is_none() && self.pending.is_none();
        if self.prepared.is_none() {
            ui.label("Sepolia ETH 또는 저장 후 다시 검증된 ERC-20을 선택하세요.");
            ui.add_space(6.0);
            ui.label(RichText::new("전송 자산").strong());
            let selected_label = transfer_asset_label(&self.transfer_asset, &self.custom_tokens);
            let mut previous_asset = self.transfer_asset.clone();
            let _ = ui.add_enabled_ui(preparing_allowed, |ui| {
                egui::ComboBox::from_id_salt("saved_transfer_asset")
                    .selected_text(selected_label)
                    .width(360.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.transfer_asset,
                            TransferAssetChoice::Native,
                            "Sepolia ETH",
                        );
                        for token in &self.custom_tokens {
                            let CustomTokenState::Verified {
                                symbol, decimals, ..
                            } = &token.state
                            else {
                                continue;
                            };
                            let symbol = symbol.as_deref().unwrap_or("심볼 없음");
                            ui.selectable_value(
                                &mut self.transfer_asset,
                                TransferAssetChoice::SavedErc20 {
                                    contract_address: token.contract_address.clone(),
                                },
                                format!(
                                    "{symbol} · decimals {decimals} · {}",
                                    token.contract_address
                                ),
                            );
                        }
                    });
            });
            if previous_asset != self.transfer_asset {
                zeroize_transfer_asset_choice(&mut previous_asset);
                clear_transfer_amount_after_asset_change(
                    &mut self.prepared,
                    &mut self.hold,
                    &mut self.amount_eth,
                    &mut self.secret_text_state_purge_pending,
                );
            }
            if let TransferAssetChoice::SavedErc20 { contract_address } = &self.transfer_asset {
                ui.label(RichText::new("선택한 저장 컨트랙트").strong());
                ui.label(RichText::new(contract_address).monospace());
                ui.label(
                    RichText::new(
                        "표시 정보는 선택 보조용입니다. 준비 시 인증된 토큰 파일과 Sepolia 응답을 backend가 처음부터 다시 검증합니다.",
                    )
                    .small()
                    .color(palette.muted),
                );
            }
            ui.add_space(6.0);
            ui.label("받는 주소");
            let _ = ui.add_enabled(
                preparing_allowed,
                egui::TextEdit::singleline(&mut self.recipient)
                    .id(recipient_text_edit_id())
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
                        .id(amount_eth_text_edit_id())
                        .hint_text("예: 0.001")
                        .desired_width(180.0),
                );
                ui.label(transfer_amount_unit(
                    &self.transfer_asset,
                    &self.custom_tokens,
                ));
            });
            let amount_valid = transfer_amount_shape_is_valid(
                self.amount_eth.trim(),
                &self.transfer_asset,
                &self.custom_tokens,
            );
            if !self.amount_eth.trim().is_empty() && !amount_valid {
                ui.colored_label(
                    palette.error,
                    "0보다 큰 금액을 선택한 자산의 decimals 범위 안에서 입력해 주세요.",
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
                                .id(custom_priority_fee_text_edit_id())
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
                                .id(custom_max_fee_text_edit_id())
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
            ui.label(match &self.transfer_asset {
                TransferAssetChoice::Native => RichText::new(
                    "일반 ETH 전송의 가스 한도는 21,000으로 고정됩니다.",
                )
                .small()
                .color(palette.muted),
                TransferAssetChoice::SavedErc20 { .. } => RichText::new(
                    "ERC-20은 exact transfer 호출을 사전 실행하고, 추정 가스에 20%를 올림해 최대 500,000 안에서 고정합니다. 토큰과 수수료용 ETH 잔액을 모두 확인합니다.",
                )
                .small()
                .color(palette.muted),
            });
            ui.add_space(8.0);
            let valid_input = valid_recipient_shape(self.recipient.trim())
                && amount_valid
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
            ui.group(|ui| match &preview {
                PreparedPreview::Native(preview) => render_transfer_preview(ui, preview),
                PreparedPreview::SavedErc20(preview) => {
                    render_erc20_transfer_preview(ui, preview);
                }
            });
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
    prepared: Option<&PreparedPreview>,
    pending: Option<PendingAction>,
) -> bool {
    prepared.is_some() && pending.is_none()
}

fn automatic_lock_reason(
    has_sensitive_state: bool,
    phase: SessionPhase,
    last_activity_at: Instant,
    now: Instant,
    focused: bool,
) -> Option<LockReason> {
    if !has_sensitive_state || matches!(phase, SessionPhase::Locking(_)) {
        return None;
    }
    if !focused {
        return Some(LockReason::FocusLost);
    }
    (now.saturating_duration_since(last_activity_at) >= INACTIVITY_LOCK_DURATION)
        .then_some(LockReason::Inactivity)
}

fn is_user_activity_event(event: &egui::Event) -> bool {
    matches!(
        event,
        egui::Event::Copy
            | egui::Event::Cut
            | egui::Event::Paste(_)
            | egui::Event::Text(_)
            | egui::Event::Key { pressed: true, .. }
            | egui::Event::PointerMoved(_)
            | egui::Event::MouseMoved(_)
            | egui::Event::PointerButton { .. }
            | egui::Event::Zoom(_)
            | egui::Event::Ime(_)
            | egui::Event::Touch { .. }
            | egui::Event::MouseWheel { .. }
    )
}

const fn lock_notice(reason: LockReason) -> &'static str {
    match reason {
        LockReason::Explicit => "지갑을 잠갔습니다. 다시 열려면 비밀번호를 입력하세요.",
        LockReason::Inactivity => {
            "5분 동안 입력이 없어 지갑을 잠갔습니다. 다시 열려면 비밀번호를 입력하세요."
        }
        LockReason::FocusLost => {
            "창의 포커스를 잃어 지갑을 잠갔습니다. 다시 열려면 비밀번호를 입력하세요."
        }
    }
}

fn zeroize_optional_string(value: &mut Option<String>) {
    if let Some(value) = value.as_mut() {
        value.zeroize();
    }
    *value = None;
}

fn zeroize_prepared_preview(preview: &mut PreparedPreview) {
    match preview {
        PreparedPreview::Native(preview) => {
            preview.recipient.zeroize();
            preview.amount_eth.zeroize();
            preview.nonce.zeroize();
            preview.fee_mode_ko.zeroize();
            preview.gas_limit.zeroize();
            preview.quoted_base_fee_per_gas_gwei.zeroize();
            preview.max_priority_fee_per_gas_gwei.zeroize();
            preview.max_fee_per_gas_gwei.zeroize();
            preview.estimated_network_fee_eth.zeroize();
            preview.max_network_fee_eth.zeroize();
            preview.max_total_eth.zeroize();
            preview.estimated_total_eth.zeroize();
            preview.quote_valid_for_seconds.zeroize();
        }
        PreparedPreview::SavedErc20(preview) => {
            preview.contract_address.zeroize();
            if let Some(symbol) = preview.symbol.as_mut() {
                symbol.zeroize();
            }
            preview.recipient.zeroize();
            preview.amount.zeroize();
            preview.nonce.zeroize();
            preview.fee_mode_ko.zeroize();
            preview.estimated_gas.zeroize();
            preview.gas_limit.zeroize();
            preview.quoted_base_fee_per_gas_gwei.zeroize();
            preview.max_priority_fee_per_gas_gwei.zeroize();
            preview.max_fee_per_gas_gwei.zeroize();
            preview.estimated_network_fee_eth.zeroize();
            preview.max_network_fee_eth.zeroize();
            preview.quote_valid_for_seconds.zeroize();
        }
    }
}

fn clear_prepared_state(prepared: &mut Option<PreparedPreview>, hold: &mut HoldToSend) {
    if let Some(preview) = prepared.as_mut() {
        zeroize_prepared_preview(preview);
    }
    *prepared = None;
    hold.reset();
}

fn zeroize_transfer_asset_choice(choice: &mut TransferAssetChoice) {
    if let TransferAssetChoice::SavedErc20 { contract_address } = choice {
        contract_address.zeroize();
    }
}

fn reset_transfer_selection_after_token_change(
    choice: &mut TransferAssetChoice,
    prepared: &mut Option<PreparedPreview>,
    hold: &mut HoldToSend,
    amount: &mut String,
    secret_text_state_purge_pending: &mut bool,
) {
    zeroize_transfer_asset_choice(choice);
    *choice = TransferAssetChoice::Native;
    clear_transfer_amount_after_asset_change(
        prepared,
        hold,
        amount,
        secret_text_state_purge_pending,
    );
}

fn clear_transfer_amount_after_asset_change(
    prepared: &mut Option<PreparedPreview>,
    hold: &mut HoldToSend,
    amount: &mut String,
    secret_text_state_purge_pending: &mut bool,
) {
    amount.zeroize();
    *secret_text_state_purge_pending = true;
    clear_prepared_state(prepared, hold);
}

fn verified_token_by_contract<'a>(
    tokens: &'a [CustomTokenSnapshot],
    contract_address: &str,
) -> Option<(&'a Option<String>, u8)> {
    tokens.iter().find_map(|token| {
        if token.contract_address != contract_address {
            return None;
        }
        match &token.state {
            CustomTokenState::Verified {
                symbol, decimals, ..
            } => Some((symbol, *decimals)),
            CustomTokenState::Unavailable { .. } => None,
        }
    })
}

fn transfer_asset_label(choice: &TransferAssetChoice, tokens: &[CustomTokenSnapshot]) -> String {
    match choice {
        TransferAssetChoice::Native => "Sepolia ETH".to_owned(),
        TransferAssetChoice::SavedErc20 { contract_address } => {
            match verified_token_by_contract(tokens, contract_address) {
                Some((symbol, decimals)) => format!(
                    "{} · decimals {decimals}",
                    symbol.as_deref().unwrap_or("심볼 없음")
                ),
                None => "다시 검증이 필요한 저장 토큰".to_owned(),
            }
        }
    }
}

fn transfer_amount_unit<'a>(
    choice: &'a TransferAssetChoice,
    tokens: &'a [CustomTokenSnapshot],
) -> &'a str {
    match choice {
        TransferAssetChoice::Native => "Sepolia ETH",
        TransferAssetChoice::SavedErc20 { contract_address } => {
            verified_token_by_contract(tokens, contract_address)
                .and_then(|(symbol, _)| symbol.as_deref())
                .unwrap_or("토큰")
        }
    }
}

fn transfer_amount_shape_is_valid(
    amount: &str,
    choice: &TransferAssetChoice,
    tokens: &[CustomTokenSnapshot],
) -> bool {
    match choice {
        TransferAssetChoice::Native => valid_amount_shape(amount),
        TransferAssetChoice::SavedErc20 { contract_address } => {
            verified_token_by_contract(tokens, contract_address).is_some_and(|(_, decimals)| {
                valid_decimal_amount_shape(amount, usize::from(decimals), 128)
            })
        }
    }
}

fn sanitize_custom_tokens(mut tokens: Vec<CustomTokenSnapshot>) -> Vec<CustomTokenSnapshot> {
    for token in &mut tokens {
        if let CustomTokenState::Unavailable { reason_ko } = &mut token.state {
            *reason_ko = safe_error(std::mem::take(reason_ko));
        }
    }
    tokens
}

fn zeroize_custom_token_snapshots(tokens: &mut Vec<CustomTokenSnapshot>) {
    for token in tokens.iter_mut() {
        token.contract_address.zeroize();
        match &mut token.state {
            CustomTokenState::Verified {
                symbol, balance, ..
            } => {
                if let Some(symbol) = symbol.as_mut() {
                    symbol.zeroize();
                }
                balance.zeroize();
            }
            CustomTokenState::Unavailable { reason_ko } => reason_ko.zeroize(),
        }
    }
    tokens.clear();
}

fn mark_snapshot_balance_stale(snapshot: Option<&mut WalletSnapshot>) {
    if let Some(snapshot) = snapshot {
        snapshot.balance_eth.zeroize();
        snapshot.balance_eth = "다시 조회 필요".to_owned();
    }
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

fn render_erc20_transfer_preview(ui: &mut egui::Ui, preview: &Erc20TransferPreview) {
    let symbol = preview.symbol.as_deref().unwrap_or("심볼 없음");
    let fields = [
        ("자산 종류", "저장·검증된 ERC-20"),
        ("토큰 컨트랙트", preview.contract_address.as_str()),
        ("컨트랙트 제공 심볼", symbol),
        ("decimals", ""),
        ("받는 주소", preview.recipient.as_str()),
        ("보낼 토큰 수량", preview.amount.as_str()),
        ("nonce", preview.nonce.as_str()),
        ("수수료 방식", preview.fee_mode_ko.as_str()),
        ("RPC 추정 가스", preview.estimated_gas.as_str()),
        ("20% 올림 후 가스 한도", preview.gas_limit.as_str()),
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
            "준비 완료 시점 남은 견적 유효 시간 (초)",
            preview.quote_valid_for_seconds.as_str(),
        ),
    ];
    for (label, value) in fields {
        ui.label(RichText::new(label).strong());
        let value = if label == "decimals" {
            preview.decimals.to_string()
        } else {
            value.to_owned()
        };
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(value).monospace().size(18.0));
        });
        ui.add_space(7.0);
    }
    let palette = StatusPalette::from_visuals(ui.visuals());
    ui.label(
        RichText::new(
            "컨트랙트, 받는 주소, 토큰 수량, 68-byte transfer calldata, 가스·EIP-1559 값이 이 미리보기에 고정됩니다. 토큰 수량과 수수료용 ETH는 서로 다른 잔액입니다.",
        )
        .small()
        .color(palette.muted),
    );
    ui.label(
        RichText::new(
            "표시 수량은 transfer 호출에 넣는 정확한 인자입니다. 전송 수수료형·리베이스·악성 토큰의 실제 수령량이나 잔액 변화는 보장하지 않으며, 프록시 구현 변경과 사전 실행 이후 채굴 전 상태 변경도 막지 못합니다.",
        )
        .small()
        .color(palette.warning),
    );
}

impl Drop for WalletApp {
    fn drop(&mut self) {
        self.active_epoch.store(u64::MAX, Ordering::SeqCst);
        self.scrub_frontend_session();
    }
}

impl eframe::App for WalletApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        let now = Instant::now();
        self.observe_automatic_lock(context, now);
        self.process_events();
        self.observe_automatic_lock(context, now);
        self.expire_secret_reveal(now);
        self.expire_generated_backup(now);
        self.purge_queued_secret_text_edit_state(context);
        let backup_ceremony_active = self.generated_backup_ceremony_active();
        context.input_mut(|input| {
            filter_generated_backup_clipboard_events(&mut input.events, backup_ceremony_active);
        });
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
                let lock_screen = self.session_controls(ui);
                if !lock_screen {
                    self.wallet_setup(ui);
                    self.account_panel(ui);
                    self.secret_management_panel(context, ui);
                    self.generated_backup_panel(context, ui);
                    self.secret_reveal_panel(context, ui);
                    self.custom_token_panel(ui);
                    self.send_panel(context, ui);
                }

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
        self.purge_queued_secret_text_edit_state(context);
    }
}

fn spawn_worker(
    mut backend: Box<dyn WalletBackend>,
    commands: Receiver<WorkerRequest>,
    events: Sender<WorkerResponse>,
    active_epoch: Arc<AtomicU64>,
) {
    std::thread::spawn(move || {
        while let Ok(request) = commands.recv() {
            let Some(response) =
                execute_worker_request(backend.as_mut(), request, active_epoch.as_ref())
            else {
                continue;
            };
            if events.send(response).is_err() {
                break;
            }
        }
        backend.lock_wallet();
    });
}

fn execute_worker_request(
    backend: &mut dyn WalletBackend,
    request: WorkerRequest,
    active_epoch: &AtomicU64,
) -> Option<WorkerResponse> {
    if request.epoch != active_epoch.load(Ordering::SeqCst) {
        backend.lock_wallet();
        drop(request);
        return None;
    }

    let epoch = request.epoch;
    let permit = SessionPermit::for_worker(epoch, active_epoch);
    let event = execute_worker_command(backend, request.command, &permit);
    if epoch != active_epoch.load(Ordering::SeqCst) {
        backend.lock_wallet();
        drop(event);
        return None;
    }
    Some(WorkerResponse { epoch, event })
}

fn execute_worker_command(
    backend: &mut dyn WalletBackend,
    command: WorkerCommand,
    permit: &SessionPermit<'_>,
) -> WorkerEvent {
    match command {
        WorkerCommand::Lock => {
            backend.lock_wallet();
            WorkerEvent::Locked
        }
        WorkerCommand::BeginGenerate {
            words,
            password,
            password_confirmation,
        } => WorkerEvent::GenerationBegun(backend.begin_generate_wallet(
            words,
            password,
            password_confirmation,
        )),
        WorkerCommand::BeginGeneratedBackupChallenge => {
            WorkerEvent::GeneratedBackupChallengeBegun(backend.begin_generated_backup_challenge())
        }
        WorkerCommand::ConfirmGenerated { confirmation } => {
            WorkerEvent::GeneratedConfirmed(backend.confirm_generated_wallet(confirmation, permit))
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
        WorkerCommand::AddCustomToken { contract_address } => {
            WorkerEvent::CustomTokenAdded(backend.add_custom_token(&contract_address))
        }
        WorkerCommand::RefreshCustomTokens => {
            WorkerEvent::CustomTokensRefreshed(backend.refresh_custom_tokens())
        }
        WorkerCommand::RemoveCustomToken { contract_address } => {
            WorkerEvent::CustomTokenRemoved(backend.remove_custom_token(&contract_address))
        }
        WorkerCommand::PrepareTransfer {
            recipient,
            amount_eth,
            fee_selection,
        } => WorkerEvent::TransferPrepared(Box::new(backend.prepare_transfer(
            &recipient,
            &amount_eth,
            fee_selection,
        ))),
        WorkerCommand::PrepareSavedErc20Transfer {
            contract_address,
            recipient,
            amount,
            fee_selection,
        } => {
            WorkerEvent::SavedErc20TransferPrepared(Box::new(backend.prepare_saved_erc20_transfer(
                &contract_address,
                &recipient,
                &amount,
                fee_selection,
                permit,
            )))
        }
        WorkerCommand::ConfirmPrepared => {
            WorkerEvent::PreparedConfirmed(backend.confirm_prepared(permit))
        }
        WorkerCommand::CancelPrepared => WorkerEvent::PreparedCancelled(backend.cancel_prepared()),
        WorkerCommand::RetryPending => WorkerEvent::Retried(backend.retry_pending(permit)),
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
    const TOKEN_CONTRACT_SENTINEL: &str = "0x1111111111111111111111111111111111111111";

    let (command_sender, command_receiver) = mpsc::channel();
    let (_unused_event_sender, event_receiver) = mpsc::channel();
    let active_epoch = Arc::new(AtomicU64::new(0));
    let mut app = WalletApp {
        commands: Some(command_sender),
        events: event_receiver,
        active_epoch,
        session_epoch: 0,
        session_phase: SessionPhase::Locked,
        last_activity_at: Instant::now(),
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
        custom_token_address: String::new(),
        custom_tokens: Vec::new(),
        transfer_asset: TransferAssetChoice::Native,
        recipient: RECIPIENT_SENTINEL.to_owned(),
        amount_eth: AMOUNT_SENTINEL.to_owned(),
        fee_mode: FeeMode::Recommended,
        custom_priority_fee_gwei: String::new(),
        custom_max_fee_gwei: String::new(),
        prepared: None,
        pending: None,
        hold: HoldToSend::default(),
        secret_hold: HoldToSend::default(),
        generated_backup: None,
        generated_backup_inputs_visible: false,
        secret_reveal: None,
        secret_text_state_purge_pending: false,
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
        || !matches!(
            app.generated_backup,
            Some(GeneratedBackupUiState::Display(_))
        )
    {
        return Err(());
    }
    if !app.handle_secret_hold_outcome(
        HoldOutcome::Triggered,
        SecretHoldAction::BeginGeneratedBackupChallenge,
    ) || app.handle_secret_hold_outcome(
        HoldOutcome::Triggered,
        SecretHoldAction::BeginGeneratedBackupChallenge,
    ) {
        return Err(());
    }
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::BeginGeneratedBackupChallenge)
    })?;
    let Some(GeneratedBackupUiState::Challenge {
        words,
        first_address,
        ..
    }) = app.generated_backup.as_mut()
    else {
        return Err(());
    };
    for word in words {
        word.push_str("marker");
    }
    first_address.push_str("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
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
        matches!(command, WorkerCommand::ConfirmGenerated { .. })
    })?;
    if app.pending.is_some()
        || app.generated_backup.is_some()
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
    if !app
        .secret_reveal
        .as_ref()
        .is_some_and(|reveal| reveal.reveal.kind() == SecretRevealKind::Mnemonic)
    {
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
    if !app
        .secret_reveal
        .as_ref()
        .is_some_and(|reveal| reveal.reveal.kind() == SecretRevealKind::AccountPrivateKey)
    {
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
    if app.pending != Some(PendingAction::RefreshCustomTokens) {
        return Err(());
    }
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::RefreshCustomTokens)
    })?;
    if app.pending.is_some() || app.custom_tokens != [headless_token_snapshot()] {
        return Err(());
    }

    app.custom_token_address = TOKEN_CONTRACT_SENTINEL.to_owned();
    app.add_custom_token();
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(
            command,
            WorkerCommand::AddCustomToken { contract_address }
                if contract_address == TOKEN_CONTRACT_SENTINEL
        )
    })?;
    if app.custom_tokens != [headless_token_snapshot()] || !app.custom_token_address.is_empty() {
        return Err(());
    }
    app.refresh_custom_tokens();
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::RefreshCustomTokens)
    })?;
    if app.custom_tokens != [headless_token_snapshot()] {
        return Err(());
    }

    app.transfer_asset = TransferAssetChoice::SavedErc20 {
        contract_address: TOKEN_CONTRACT_SENTINEL.to_owned(),
    };
    app.recipient = RECIPIENT_SENTINEL.to_owned();
    app.amount_eth = AMOUNT_SENTINEL.to_owned();
    app.fee_mode = FeeMode::Recommended;
    app.prepare_transfer();
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(
            command,
            WorkerCommand::PrepareSavedErc20Transfer {
                contract_address,
                recipient,
                amount,
                fee_selection: FeeSelection::Recommended,
            } if contract_address == TOKEN_CONTRACT_SENTINEL
                && recipient == RECIPIENT_SENTINEL
                && amount == AMOUNT_SENTINEL
        )
    })?;
    if app.prepared.as_ref() != Some(&PreparedPreview::SavedErc20(headless_erc20_preview())) {
        return Err(());
    }
    if !app.handle_hold_outcome(HoldOutcome::Triggered)
        || app.handle_hold_outcome(HoldOutcome::Triggered)
    {
        return Err(());
    }
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::ConfirmPrepared)
    })?;
    if app.prepared.is_some()
        || app.transfer_asset != TransferAssetChoice::Native
        || !app.amount_eth.is_empty()
        || !app.custom_tokens.is_empty()
    {
        return Err(());
    }
    app.refresh_custom_tokens();
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::RefreshCustomTokens)
    })?;
    if app.custom_tokens != [headless_token_snapshot()] {
        return Err(());
    }
    app.remove_custom_token(TOKEN_CONTRACT_SENTINEL.to_owned());
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(
            command,
            WorkerCommand::RemoveCustomToken { contract_address }
                if contract_address == TOKEN_CONTRACT_SENTINEL
        )
    })?;
    if !app.custom_tokens.is_empty() {
        return Err(());
    }

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

    app.recipient = RECIPIENT_SENTINEL.to_owned();
    app.amount_eth = AMOUNT_SENTINEL.to_owned();
    app.fee_mode = FeeMode::Recommended;
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
        || app.prepared.as_ref()
            != Some(&PreparedPreview::Native(headless_preview(
                FeeMode::Recommended,
            )))
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
    if app.pending.is_some()
        || app.prepared.as_ref()
            != Some(&PreparedPreview::Native(headless_preview(FeeMode::Faster)))
    {
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
    if app.pending.is_some()
        || app.prepared.as_ref()
            != Some(&PreparedPreview::Native(headless_preview(FeeMode::Custom)))
    {
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
    if app.pending.is_some() || app.last_transaction_hash.as_deref() != Some("headless-retried") {
        return Err(());
    }

    app.password = "headless-lock-password".to_owned();
    app.password_confirmation = "headless-lock-password".to_owned();
    app.old_password = "headless-old-password".to_owned();
    app.imported_secret = "headless-import-secret".to_owned();
    app.reauth_password = "headless-reauth-password".to_owned();
    app.custom_token_address = TOKEN_CONTRACT_SENTINEL.to_owned();
    app.custom_tokens = vec![headless_token_snapshot()];
    app.recipient = RECIPIENT_SENTINEL.to_owned();
    app.amount_eth = AMOUNT_SENTINEL.to_owned();
    app.custom_priority_fee_gwei = "1".to_owned();
    app.custom_max_fee_gwei = "3".to_owned();
    app.prepared = Some(PreparedPreview::Native(headless_preview(
        FeeMode::Recommended,
    )));
    app.pending = Some(PendingAction::Refresh);
    app.secret_reveal = TimedSecretReveal::new(
        headless_reveal(SecretRevealKind::AccountPrivateKey),
        Instant::now(),
    );
    let previous_epoch = app.session_epoch;
    app.request_lock(LockReason::Explicit);
    if app.session_epoch != previous_epoch + 1
        || !matches!(
            app.session_phase,
            SessionPhase::Locking(LockReason::Explicit)
        )
        || app.pending.is_some()
        || app.snapshot.is_some()
        || app.prepared.is_some()
        || app.secret_reveal.is_some()
        || !app.custom_tokens.is_empty()
        || !app.password.is_empty()
        || !app.password_confirmation.is_empty()
        || !app.old_password.is_empty()
        || !app.imported_secret.is_empty()
        || !app.reauth_password.is_empty()
        || !app.recipient.is_empty()
        || !app.amount_eth.is_empty()
        || app.last_transaction_hash.is_some()
    {
        return Err(());
    }

    // A valid unlock attempt while the backend lock is awaiting its ACK must
    // be dropped locally and must not enqueue a second worker request.
    app.password = "headless-lock-password".to_owned();
    app.open_wallet();
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::Lock)
    })?;
    if app.session_phase != SessionPhase::Locked || app.snapshot.is_some() {
        return Err(());
    }

    // Locked handlers must not route export, token, transfer, or retry work.
    app.reauth_password = "headless-lock-password".to_owned();
    if app.handle_secret_hold_outcome(HoldOutcome::Triggered, SecretHoldAction::ExportMnemonic) {
        return Err(());
    }
    app.custom_token_address = TOKEN_CONTRACT_SENTINEL.to_owned();
    app.add_custom_token();
    app.recipient = RECIPIENT_SENTINEL.to_owned();
    app.amount_eth = AMOUNT_SENTINEL.to_owned();
    app.prepare_transfer();
    app.retry_pending();

    if backend.calls
        != [
            "begin-generate-12",
            "begin-generated-challenge",
            "confirm-generated",
            "export-mnemonic",
            "export-private-key",
            "import-mnemonic",
            "import-private-key",
            "migrate",
            "open",
            "token-refresh",
            "token-add",
            "token-refresh",
            "prepare-token",
            "confirm",
            "token-refresh",
            "token-remove",
            "begin-generate-12",
            "cancel-generated",
            "prepare-recommended",
            "confirm",
            "prepare-faster",
            "cancel",
            "prepare-custom",
            "cancel",
            "retry",
            "lock",
        ]
        || command_receiver.try_recv().is_ok()
    {
        return Err(());
    }

    Ok(HeadlessSmokeEvidence {
        transitions_checked: 74,
        backend_routes_checked: backend.calls.len(),
    })
}

fn route_headless_command(
    app: &mut WalletApp,
    command_receiver: &Receiver<WorkerRequest>,
    backend: &mut dyn WalletBackend,
    expected: impl FnOnce(&WorkerCommand) -> bool,
) -> Result<(), ()> {
    let request = command_receiver.try_recv().map_err(|_| ())?;
    if request.epoch != app.session_epoch || !expected(&request.command) {
        return Err(());
    }
    let response = execute_worker_request(backend, request, app.active_epoch.as_ref()).ok_or(())?;
    if response.epoch != app.session_epoch {
        return Err(());
    }
    app.apply_worker_event(response.event);
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

fn headless_erc20_preview() -> Erc20TransferPreview {
    Erc20TransferPreview {
        contract_address: "0x1111111111111111111111111111111111111111".to_owned(),
        symbol: Some("TOK".to_owned()),
        decimals: 18,
        recipient: "headless-recipient".to_owned(),
        amount: "1.25".to_owned(),
        nonce: "headless-nonce".to_owned(),
        fee_mode_ko: "추천".to_owned(),
        estimated_gas: "50000".to_owned(),
        gas_limit: "60000".to_owned(),
        quoted_base_fee_per_gas_gwei: "1".to_owned(),
        max_priority_fee_per_gas_gwei: "1".to_owned(),
        max_fee_per_gas_gwei: "3".to_owned(),
        estimated_network_fee_eth: "0.0001".to_owned(),
        max_network_fee_eth: "0.00018".to_owned(),
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

fn headless_generated_backup_reveal() -> GeneratedBackupReveal {
    GeneratedBackupReveal::new(
        Zeroizing::new("headless backup marker".to_owned()),
        Zeroizing::new("headless account marker".to_owned()),
        Instant::now() + Duration::from_secs(120),
    )
}

fn headless_token_snapshot() -> CustomTokenSnapshot {
    CustomTokenSnapshot {
        contract_address: "0x1111111111111111111111111111111111111111".to_owned(),
        state: CustomTokenState::Verified {
            symbol: Some("TOK".to_owned()),
            decimals: 18,
            balance: "12.5".to_owned(),
        },
    }
}

#[derive(Default)]
struct HeadlessBackend {
    calls: Vec<&'static str>,
}

impl WalletBackend for HeadlessBackend {
    fn lock_wallet(&mut self) {
        self.calls.push("lock");
    }

    fn begin_generate_wallet(
        &mut self,
        words: NewMnemonicWords,
        _password: SensitiveText,
        _password_confirmation: SensitiveText,
    ) -> Result<GeneratedBackupReveal, String> {
        self.calls.push(match words {
            NewMnemonicWords::Twelve => "begin-generate-12",
            NewMnemonicWords::TwentyFour => "begin-generate-24",
        });
        Ok(headless_generated_backup_reveal())
    }

    fn begin_generated_backup_challenge(&mut self) -> Result<GeneratedBackupChallenge, String> {
        self.calls.push("begin-generated-challenge");
        Ok(GeneratedBackupChallenge::new(
            [1, 2, 3, 4],
            Instant::now() + Duration::from_secs(120),
        ))
    }

    fn confirm_generated_wallet(
        &mut self,
        _confirmation: GeneratedBackupConfirmation,
        _permit: &SessionPermit<'_>,
    ) -> Result<WalletSnapshot, String> {
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

    fn add_custom_token(
        &mut self,
        contract_address: &str,
    ) -> Result<Vec<CustomTokenSnapshot>, String> {
        if contract_address != "0x1111111111111111111111111111111111111111" {
            return Err("headless token mismatch".to_owned());
        }
        self.calls.push("token-add");
        Ok(vec![headless_token_snapshot()])
    }

    fn refresh_custom_tokens(&mut self) -> Result<Vec<CustomTokenSnapshot>, String> {
        self.calls.push("token-refresh");
        Ok(vec![headless_token_snapshot()])
    }

    fn remove_custom_token(
        &mut self,
        contract_address: &str,
    ) -> Result<Vec<CustomTokenSnapshot>, String> {
        if contract_address != "0x1111111111111111111111111111111111111111" {
            return Err("headless token mismatch".to_owned());
        }
        self.calls.push("token-remove");
        Ok(Vec::new())
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

    fn prepare_saved_erc20_transfer(
        &mut self,
        contract_address: &str,
        recipient: &str,
        amount: &str,
        fee_selection: FeeSelection,
        _permit: &SessionPermit<'_>,
    ) -> Result<Erc20TransferPreview, String> {
        if contract_address != "0x1111111111111111111111111111111111111111"
            || recipient != "headless-recipient"
            || amount != "headless-amount"
            || fee_selection != FeeSelection::Recommended
        {
            return Err("headless ERC20 input mismatch".to_owned());
        }
        self.calls.push("prepare-token");
        Ok(headless_erc20_preview())
    }

    fn confirm_prepared(&mut self, _permit: &SessionPermit<'_>) -> Result<SendReceipt, String> {
        self.calls.push("confirm");
        Ok(SendReceipt {
            transaction_hash: "headless-confirmed".to_owned(),
        })
    }

    fn cancel_prepared(&mut self) -> Result<(), String> {
        self.calls.push("cancel");
        Ok(())
    }

    fn retry_pending(&mut self, _permit: &SessionPermit<'_>) -> Result<SendReceipt, String> {
        self.calls.push("retry");
        Ok(SendReceipt {
            transaction_hash: "headless-retried".to_owned(),
        })
    }
}

fn valid_password(password: &str) -> bool {
    password.len() >= MINIMUM_PASSWORD_BYTES
}

fn password_text_edit_id() -> egui::Id {
    egui::Id::new("sepolia-demo-secret-password")
}

fn password_confirmation_text_edit_id() -> egui::Id {
    egui::Id::new("sepolia-demo-secret-password-confirmation")
}

fn old_password_text_edit_id() -> egui::Id {
    egui::Id::new("sepolia-demo-secret-old-password")
}

fn imported_secret_text_edit_id() -> egui::Id {
    egui::Id::new("sepolia-demo-secret-import")
}

fn reauth_password_text_edit_id() -> egui::Id {
    egui::Id::new("sepolia-demo-secret-reauth-password")
}

fn generated_backup_word_text_edit_id(index: usize) -> egui::Id {
    egui::Id::new(("sepolia-demo-generated-backup-word", index))
}

fn generated_backup_address_text_edit_id() -> egui::Id {
    egui::Id::new("sepolia-demo-generated-backup-address")
}

fn custom_token_address_text_edit_id() -> egui::Id {
    egui::Id::new("sepolia-demo-custom-token-address")
}

fn recipient_text_edit_id() -> egui::Id {
    egui::Id::new("sepolia-demo-transfer-recipient")
}

fn amount_eth_text_edit_id() -> egui::Id {
    egui::Id::new("sepolia-demo-transfer-amount")
}

fn custom_priority_fee_text_edit_id() -> egui::Id {
    egui::Id::new("sepolia-demo-transfer-priority-fee")
}

fn custom_max_fee_text_edit_id() -> egui::Id {
    egui::Id::new("sepolia-demo-transfer-max-fee")
}

fn secret_text_edit_ids() -> [egui::Id; 15] {
    [
        password_text_edit_id(),
        password_confirmation_text_edit_id(),
        old_password_text_edit_id(),
        imported_secret_text_edit_id(),
        reauth_password_text_edit_id(),
        generated_backup_word_text_edit_id(0),
        generated_backup_word_text_edit_id(1),
        generated_backup_word_text_edit_id(2),
        generated_backup_word_text_edit_id(3),
        generated_backup_address_text_edit_id(),
        custom_token_address_text_edit_id(),
        recipient_text_edit_id(),
        amount_eth_text_edit_id(),
        custom_priority_fee_text_edit_id(),
        custom_max_fee_text_edit_id(),
    ]
}

fn purge_secret_text_edit_state(context: &egui::Context) {
    let ids = secret_text_edit_ids();
    context.memory_mut(|memory| {
        for id in ids {
            memory.surrender_focus(id);
        }
    });
    for id in ids {
        if let Some(mut state) = egui::widgets::text_edit::TextEditState::load(context, id) {
            state.clear_undoer();
        }
        context.data_mut(|data| {
            data.remove::<egui::widgets::text_edit::TextEditState>(id);
        });
    }
}

fn numbered_backup_words(phrase: &str) -> impl Iterator<Item = (usize, &str)> {
    phrase
        .split_ascii_whitespace()
        .enumerate()
        .map(|(index, word)| (index + 1, word))
}

fn valid_backup_word_shape(word: &str) -> bool {
    !word.is_empty() && word.len() <= 8 && word.bytes().all(|byte| byte.is_ascii_lowercase())
}

fn valid_backup_address_shape(address: &str) -> bool {
    address.len() == 42
        && address.starts_with("0x")
        && address.as_bytes()[2..].iter().all(u8::is_ascii_hexdigit)
}

fn filter_generated_backup_clipboard_events(events: &mut Vec<egui::Event>, active: bool) {
    if active {
        events.retain_mut(retain_generated_backup_event);
    }
}

fn retain_generated_backup_event(event: &mut egui::Event) -> bool {
    match event {
        egui::Event::Copy | egui::Event::Cut => false,
        egui::Event::Paste(text) => {
            text.zeroize();
            false
        }
        _ => true,
    }
}

fn valid_recipient_shape(recipient: &str) -> bool {
    recipient.len() == 42
        && recipient.starts_with("0x")
        && recipient.as_bytes()[2..].iter().all(u8::is_ascii_hexdigit)
        && recipient.as_bytes()[2..].iter().any(|byte| *byte != b'0')
}

fn valid_amount_shape(amount: &str) -> bool {
    valid_decimal_amount_shape(amount, 18, 128)
}

fn valid_decimal_amount_shape(amount: &str, decimals: usize, maximum_bytes: usize) -> bool {
    if amount.is_empty()
        || amount.len() > maximum_bytes
        || amount.trim() != amount
        || !amount.bytes().any(|byte| matches!(byte, b'1'..=b'9'))
    {
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
        !digits.is_empty()
            && digits.len() <= decimals
            && digits.bytes().all(|byte| byte.is_ascii_digit())
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
    "백업 확인에 실패했습니다. 지갑은 저장되지 않았습니다.",
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
    "커스텀 토큰은 v2 지갑에서만 사용할 수 있습니다. v1 지갑을 먼저 이전해 주세요.",
    "토큰 컨트랙트 주소 형식이나 체크섬을 확인해 주세요.",
    "해당 Sepolia 주소에서 컨트랙트 코드를 찾지 못했습니다.",
    "토큰 컨트랙트 정보를 확인하지 못했습니다.",
    "토큰 컨트랙트의 표준 메타데이터 응답이 올바르지 않습니다.",
    "저장 후 토큰 컨트랙트 코드가 달라져 메타데이터와 잔액을 숨겼습니다.",
    "저장 후 토큰 메타데이터가 달라져 메타데이터와 잔액을 숨겼습니다.",
    "이미 추가한 토큰 컨트랙트입니다.",
    "커스텀 토큰은 최대 32개까지 추가할 수 있습니다.",
    "인증된 목록에서 해당 저장 토큰 컨트랙트를 찾지 못했습니다.",
    "토큰 컨트랙트가 정확한 transfer 사전 실행을 거부했습니다.",
    "토큰 전송 가스 추정값이 허용 범위를 벗어났습니다.",
    "보낼 토큰 잔액이 부족합니다.",
    "인증된 토큰 목록이 손상되었거나 현재 v2 지갑과 일치하지 않습니다.",
    "인증된 토큰 목록을 안전하게 저장하지 못했습니다.",
    "다른 토큰 목록 작업이 끝나거나 준비된 전송을 취소한 뒤 다시 시도해 주세요.",
    "토큰 목록이 다른 작업에서 변경되었습니다. 새로고침한 뒤 다시 시도해 주세요.",
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
    "일반 ETH 전송은 가스 추정값이 정확히 21,000이어야 합니다.",
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
        ALLOWED_BACKEND_ERRORS, CustomTokenSnapshot, CustomTokenState, FeeSelection,
        GENERIC_BACKEND_ERROR, HoldInput, HoldOutcome, HoldToSend, PreparedPreview,
        SEND_HOLD_DURATION, SendReceipt, StatusPalette, TransferAssetChoice, TransferPreview,
        WalletBackend, WalletSnapshot, WorkerCommand, WorkerEvent, automatic_lock_reason,
        clear_prepared_state, confirmation_enabled, execute_worker_command, execute_worker_request,
        hold_to_send_button, hold_to_send_input, preview_fields, run_headless_smoke, safe_error,
        sanitize_custom_tokens, valid_amount_shape, valid_gwei_shape, valid_password,
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

    fn run_secret_text_frame(
        context: &egui::Context,
        id: egui::Id,
        text: &mut String,
        request_focus: bool,
        time: f64,
        events: Vec<egui::Event>,
    ) {
        context.begin_pass(hold_frame_input(time, events));
        let response = egui::CentralPanel::default()
            .show(context, |ui| {
                ui.add(egui::TextEdit::singleline(text).id(id).password(true))
            })
            .inner;
        if request_focus {
            response.request_focus();
        }
        let _ = context.end_pass();
    }

    fn undo_key_event() -> egui::Event {
        egui::Event::Key {
            key: egui::Key::Z,
            physical_key: Some(egui::Key::Z),
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::CTRL,
        }
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
    fn automatic_lock_policy_is_focus_first_and_timeout_inclusive() {
        let start = Instant::now();
        assert_eq!(
            automatic_lock_reason(
                false,
                super::SessionPhase::Locked,
                start,
                start + super::INACTIVITY_LOCK_DURATION,
                false,
            ),
            None,
            "a pristine first frame must not enqueue a pointless lock"
        );
        assert_eq!(
            automatic_lock_reason(
                true,
                super::SessionPhase::Unlocked,
                start,
                start + Duration::from_secs(1),
                false,
            ),
            Some(super::LockReason::FocusLost)
        );
        assert_eq!(
            automatic_lock_reason(
                true,
                super::SessionPhase::Unlocked,
                start,
                start + super::INACTIVITY_LOCK_DURATION - Duration::from_nanos(1),
                true,
            ),
            None
        );
        assert_eq!(
            automatic_lock_reason(
                true,
                super::SessionPhase::Unlocked,
                start,
                start + super::INACTIVITY_LOCK_DURATION,
                true,
            ),
            Some(super::LockReason::Inactivity)
        );
        assert_eq!(
            automatic_lock_reason(
                true,
                super::SessionPhase::Locking(super::LockReason::Explicit),
                start,
                start + super::INACTIVITY_LOCK_DURATION,
                false,
            ),
            None,
            "locking must be idempotent even if focus remains lost"
        );
    }

    #[test]
    fn first_unfocused_frame_is_idle_but_same_frame_unlock_is_immediately_relocked() {
        let (commands, command_receiver) = std::sync::mpsc::channel();
        let (_event_sender, events) = std::sync::mpsc::channel();
        let mut app = test_app(commands, events);
        app.scrub_frontend_session();
        app.session_phase = super::SessionPhase::Locked;
        let now = Instant::now();
        app.last_activity_at = now;

        let context = egui::Context::default();
        context.begin_pass(egui::RawInput {
            focused: false,
            ..Default::default()
        });
        app.observe_automatic_lock(&context, now);
        assert!(command_receiver.try_recv().is_err());

        app.apply_worker_event(WorkerEvent::Opened(Ok(super::headless_snapshot(
            super::WalletKind::LegacyV1RawPrivateKey,
        ))));
        app.observe_automatic_lock(&context, now);
        let _ = context.end_pass();

        assert!(matches!(
            app.session_phase,
            super::SessionPhase::Locking(super::LockReason::FocusLost)
        ));
        assert!(app.snapshot.is_none());
        assert!(matches!(
            command_receiver.try_recv(),
            Ok(super::WorkerRequest {
                epoch: 1,
                command: WorkerCommand::Lock,
            })
        ));
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
        let source = include_str!("ui.rs").replace("\r\n", "\n");
        let production = source
            .split("#[cfg(test)]\nmod tests")
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
    fn production_session_permit_has_no_constructible_always_current_bypass() {
        let ui_source = include_str!("ui.rs").replace("\r\n", "\n");
        let ui_production = ui_source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("UI production prefix");
        assert_eq!(
            ui_production.matches("impl<'a> SessionPermit<'a>").count(),
            1
        );
        assert_eq!(ui_production.matches("fn for_worker(").count(), 1);
        assert!(!ui_production.contains("pub(crate) fn for_worker("));
        assert!(ui_production.contains("#[cfg(test)]\n    pub(crate) fn current_for_test("));
        assert!(ui_production.contains("#[cfg(test)]\n    pub(crate) fn revoke_on_check("));

        let backend_source = include_str!("backend.rs").replace("\r\n", "\n");
        let backend_production = backend_source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("backend production prefix");
        assert_eq!(
            backend_production
                .matches("fn confirm_prepared_with_permit(")
                .count(),
            1
        );
        assert_eq!(
            backend_production
                .matches("fn retry_pending_with_permit(")
                .count(),
            1
        );
        assert_eq!(
            backend_production.matches("pub fn retry_pending(").count(),
            1
        );
        assert!(!backend_production.contains("pub fn retry_pending(&mut self)"));
        assert!(
            backend_production.contains("#[cfg(test)]\n    fn confirm_prepared_inner(&mut self)")
        );
        assert!(backend_production.contains("#[cfg(test)]\n    fn retry_pending_inner(&mut self)"));
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
    fn generated_backup_dtos_and_worker_envelopes_keep_secret_trait_boundaries() {
        fn assert_clone_copy<T: Clone + Copy>() {}
        fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
            let (_, tail) = source.split_once(start).expect("source start marker");
            let (body, _) = tail.split_once(end).expect("source end marker");
            body
        }
        fn declaration<'a>(source: &'a str, marker: &str) -> &'a str {
            let marker_offset = source.find(marker).expect("declaration marker");
            let start = source[..marker_offset]
                .rfind("\n\n")
                .map_or(0, |offset| offset + 2);
            let end = source[marker_offset..]
                .find("\n}\n")
                .map(|offset| marker_offset + offset + 3)
                .expect("declaration end");
            &source[start..end]
        }

        assert_clone_copy::<super::GeneratedBackupChallenge>();
        let source = include_str!("ui.rs");
        let reveal_body = section(
            source,
            "pub struct GeneratedBackupReveal",
            "impl GeneratedBackupReveal",
        );
        let confirmation_body = section(
            source,
            "pub struct GeneratedBackupConfirmation",
            "impl GeneratedBackupConfirmation",
        );
        for secret_dto in [
            declaration(source, "pub struct GeneratedBackupReveal"),
            declaration(source, "pub struct GeneratedBackupConfirmation"),
        ] {
            assert!(!secret_dto.contains("derive("));
            assert!(!secret_dto.contains("Serialize"));
        }
        assert!(reveal_body.matches("Zeroizing<String>").count() >= 2);
        assert!(confirmation_body.matches("SensitiveText").count() >= 2);

        let challenge_declaration = declaration(source, "pub struct GeneratedBackupChallenge");
        let challenge_body = section(
            source,
            "pub struct GeneratedBackupChallenge",
            "impl GeneratedBackupChallenge",
        );
        assert!(challenge_declaration.contains("#[derive(Clone, Copy, Eq, PartialEq)]"));
        assert!(challenge_body.contains("positions:"));
        assert!(challenge_body.contains("expires_at:"));
        for forbidden in [
            "phrase",
            "mnemonic",
            "expected",
            "first_address",
            "SensitiveText",
            "Zeroizing",
            "Serialize",
            "Debug",
        ] {
            assert!(!challenge_body.contains(forbidden));
        }

        let command = declaration(source, "enum WorkerCommand");
        let event = declaration(source, "enum WorkerEvent");
        let response = declaration(source, "struct WorkerResponse");
        for envelope in [command, event, response] {
            assert!(!envelope.contains("#[derive(Clone"));
            assert!(!envelope.contains("Debug"));
            assert!(!envelope.contains("Serialize"));
        }
        for type_name in [
            "GeneratedBackupReveal",
            "GeneratedBackupConfirmation",
            "WorkerCommand",
            "WorkerEvent",
            "WorkerResponse",
        ] {
            assert!(!source.contains(&format!("impl Clone for {type_name}")));
            assert!(!source.contains(&format!("impl Copy for {type_name}")));
            assert!(!source.contains(&format!("impl Debug for {type_name}")));
            assert!(!source.contains(&format!("impl serde::Serialize for {type_name}")));
        }
    }

    #[test]
    fn custom_token_unavailable_reason_crosses_the_same_error_allowlist() {
        let tokens = sanitize_custom_tokens(vec![CustomTokenSnapshot {
            contract_address: "0x1111111111111111111111111111111111111111".to_owned(),
            state: CustomTokenState::Unavailable {
                reason_ko: "raw-rpc-token-marker".to_owned(),
            },
        }]);
        let CustomTokenState::Unavailable { reason_ko } = &tokens[0].state else {
            panic!("expected unavailable token state");
        };
        assert_eq!(reason_ko, GENERIC_BACKEND_ERROR);
        assert_eq!(tokens[0].contract_address.len(), 42);
    }

    #[test]
    fn failed_token_refresh_clears_previously_rendered_metadata() {
        let (command_sender, _command_receiver) = std::sync::mpsc::channel();
        let (_event_sender, event_receiver) = std::sync::mpsc::channel();
        let mut app = test_app(command_sender, event_receiver);
        app.custom_tokens = vec![super::headless_token_snapshot()];
        app.pending = Some(super::PendingAction::RefreshCustomTokens);
        app.apply_worker_event(WorkerEvent::CustomTokensRefreshed(Err(
            "raw-rpc-token-marker".to_owned(),
        )));
        assert!(app.custom_tokens.is_empty());
        assert!(app.pending.is_none());
        assert_eq!(app.error.as_deref(), Some(GENERIC_BACKEND_ERROR));
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
        commands: std::sync::mpsc::Sender<super::WorkerRequest>,
        events: std::sync::mpsc::Receiver<super::WorkerResponse>,
    ) -> super::WalletApp {
        super::WalletApp {
            commands: Some(commands),
            events,
            active_epoch: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            session_epoch: 0,
            session_phase: super::SessionPhase::Unlocked,
            last_activity_at: Instant::now(),
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
            snapshot: Some(super::headless_snapshot(super::WalletKind::V2Mnemonic {
                word_count: 12,
            })),
            custom_token_address: String::new(),
            custom_tokens: Vec::new(),
            transfer_asset: TransferAssetChoice::Native,
            recipient: String::new(),
            amount_eth: String::new(),
            fee_mode: super::FeeMode::Recommended,
            custom_priority_fee_gwei: String::new(),
            custom_max_fee_gwei: String::new(),
            prepared: None,
            pending: None,
            hold: HoldToSend::default(),
            secret_hold: HoldToSend::default(),
            generated_backup: None,
            generated_backup_inputs_visible: false,
            secret_reveal: None,
            secret_text_state_purge_pending: false,
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
        app.prepared = Some(PreparedPreview::Native(exact_preview()));

        assert!(!app.handle_hold_outcome(HoldOutcome::Idle));
        assert!(app.handle_hold_outcome(HoldOutcome::Triggered));
        assert!(!app.handle_hold_outcome(HoldOutcome::Triggered));
        assert!(matches!(
            command_receiver.try_recv(),
            Ok(super::WorkerRequest {
                command: WorkerCommand::ConfirmPrepared,
                ..
            })
        ));
        assert!(command_receiver.try_recv().is_err());
    }

    #[test]
    fn numbered_backup_words_preserve_all_twenty_four_ordinals_and_warning_is_one_attempt() {
        let phrase = (1..=24)
            .map(|index| format!("word{index:02}"))
            .collect::<Vec<_>>()
            .join(" ");
        let numbered = super::numbered_backup_words(&phrase).collect::<Vec<_>>();
        assert_eq!(numbered.len(), 24);
        assert!(
            numbered
                .iter()
                .enumerate()
                .all(|(index, (ordinal, word))| *ordinal == index + 1
                    && *word == format!("word{:02}", index + 1))
        );
        assert!(super::GENERATED_BACKUP_ONE_ATTEMPT_WARNING.contains("단 한 번"));
        assert!(super::GENERATED_BACKUP_ONE_ATTEMPT_WARNING.contains("저장되지"));
    }

    #[test]
    fn display_is_dropped_before_challenge_request_and_deadline_is_carried_forward() {
        let (commands, command_receiver) = std::sync::mpsc::channel();
        let (_event_sender, events) = std::sync::mpsc::channel();
        let mut app = test_app(commands, events);
        let deadline = Instant::now() + Duration::from_secs(120);
        app.generated_backup = Some(super::GeneratedBackupUiState::Display(
            super::GeneratedBackupReveal::new(
                zeroize::Zeroizing::new("headless-display-marker".to_owned()),
                zeroize::Zeroizing::new("0x0000000000000000000000000000000000000000".to_owned()),
                deadline,
            ),
        ));

        app.begin_generated_backup_challenge();
        assert!(app.generated_backup.is_none());
        assert!(app.secret_text_state_purge_pending);
        assert!(matches!(
            command_receiver.try_recv(),
            Ok(super::WorkerRequest {
                command: WorkerCommand::BeginGeneratedBackupChallenge,
                ..
            })
        ));
        app.apply_worker_event(WorkerEvent::GeneratedBackupChallengeBegun(Ok(
            super::GeneratedBackupChallenge::new([2, 5, 8, 11], deadline),
        )));
        let Some(super::GeneratedBackupUiState::Challenge {
            challenge,
            words,
            first_address,
        }) = app.generated_backup.as_ref()
        else {
            panic!("challenge state required");
        };
        assert_eq!(challenge.expires_at(), deadline);
        assert!(words.iter().all(|word| word.is_empty()));
        assert!(first_address.is_empty());
        assert!(!app.generated_backup_inputs_visible);
    }

    #[test]
    fn generated_backup_clipboard_filter_scrubs_paste_before_removing_it() {
        let mut paste = egui::Event::Paste("owned-paste-marker".to_owned());
        assert!(!super::retain_generated_backup_event(&mut paste));
        assert!(matches!(&paste, egui::Event::Paste(value) if value.is_empty()));

        let mut active = vec![
            egui::Event::Copy,
            egui::Event::Cut,
            egui::Event::Paste("second-owned-marker".to_owned()),
            egui::Event::Text("ordinary-input".to_owned()),
        ];
        super::filter_generated_backup_clipboard_events(&mut active, true);
        assert_eq!(active.len(), 1);
        assert!(matches!(active.first(), Some(egui::Event::Text(_))));

        let mut inactive = vec![egui::Event::Paste("inactive-marker".to_owned())];
        super::filter_generated_backup_clipboard_events(&mut inactive, false);
        assert_eq!(inactive.len(), 1);
    }

    #[test]
    fn final_backup_hold_dispatches_confirmation_exactly_once() {
        let (commands, command_receiver) = std::sync::mpsc::channel();
        let (_event_sender, events) = std::sync::mpsc::channel();
        let mut app = test_app(commands, events);
        app.generated_backup = Some(super::GeneratedBackupUiState::Challenge {
            challenge: super::GeneratedBackupChallenge::new(
                [1, 2, 3, 4],
                Instant::now() + Duration::from_secs(120),
            ),
            words: std::array::from_fn(|_| zeroize::Zeroizing::new("marker".to_owned())),
            first_address: zeroize::Zeroizing::new(
                "0x0000000000000000000000000000000000000000".to_owned(),
            ),
        });

        assert!(app.handle_secret_hold_outcome(
            HoldOutcome::Triggered,
            super::SecretHoldAction::ConfirmGeneratedBackup,
        ));
        assert!(!app.handle_secret_hold_outcome(
            HoldOutcome::Triggered,
            super::SecretHoldAction::ConfirmGeneratedBackup,
        ));
        assert!(app.generated_backup.is_none());
        assert!(!app.generated_backup_inputs_visible);
        assert!(matches!(
            command_receiver.try_recv(),
            Ok(super::WorkerRequest {
                command: WorkerCommand::ConfirmGenerated { .. },
                ..
            })
        ));
        assert!(command_receiver.try_recv().is_err());
    }

    #[test]
    fn generated_backup_display_and_challenge_expire_at_the_exact_shared_deadline() {
        for challenge_stage in [false, true] {
            let (commands, command_receiver) = std::sync::mpsc::channel();
            let (_event_sender, events) = std::sync::mpsc::channel();
            let mut app = test_app(commands, events);
            let start = Instant::now();
            let deadline = start + Duration::from_secs(120);
            app.generated_backup = Some(if challenge_stage {
                super::GeneratedBackupUiState::Challenge {
                    challenge: super::GeneratedBackupChallenge::new([1, 2, 3, 4], deadline),
                    words: std::array::from_fn(|_| {
                        zeroize::Zeroizing::new("headless-input-marker".to_owned())
                    }),
                    first_address: zeroize::Zeroizing::new(
                        "0x0000000000000000000000000000000000000000".to_owned(),
                    ),
                }
            } else {
                super::GeneratedBackupUiState::Display(super::GeneratedBackupReveal::new(
                    zeroize::Zeroizing::new("headless-display-marker".to_owned()),
                    zeroize::Zeroizing::new(
                        "0x0000000000000000000000000000000000000000".to_owned(),
                    ),
                    deadline,
                ))
            });
            app.generated_backup_inputs_visible = true;

            app.expire_generated_backup(deadline - Duration::from_nanos(1));
            assert!(app.generated_backup.is_some());
            assert!(command_receiver.try_recv().is_err());

            app.expire_generated_backup(deadline);
            assert!(app.generated_backup.is_none());
            assert!(!app.generated_backup_inputs_visible);
            assert!(app.secret_text_state_purge_pending);
            assert!(app.pending == Some(super::PendingAction::CancelGenerated));
            assert!(matches!(
                command_receiver.try_recv(),
                Ok(super::WorkerRequest {
                    command: WorkerCommand::CancelGenerated,
                    ..
                })
            ));
            app.expire_generated_backup(deadline + Duration::from_secs(1));
            assert!(command_receiver.try_recv().is_err());
        }
    }

    #[test]
    fn challenge_text_undo_cannot_resurrect_after_cancel_confirm_or_lock() {
        for transition in 0..3 {
            let context = egui::Context::default();
            let (commands, _command_receiver) = std::sync::mpsc::channel();
            let (_event_sender, events) = std::sync::mpsc::channel();
            let mut app = test_app(commands, events);
            app.generated_backup = Some(super::GeneratedBackupUiState::Challenge {
                challenge: super::GeneratedBackupChallenge::new(
                    [1, 2, 3, 4],
                    Instant::now() + Duration::from_secs(120),
                ),
                words: std::array::from_fn(|index| {
                    zeroize::Zeroizing::new(if index == 0 {
                        String::new()
                    } else {
                        "marker".to_owned()
                    })
                }),
                first_address: zeroize::Zeroizing::new(
                    "0x0000000000000000000000000000000000000000".to_owned(),
                ),
            });
            let id = super::generated_backup_word_text_edit_id(0);
            let Some(super::GeneratedBackupUiState::Challenge { words, .. }) =
                app.generated_backup.as_mut()
            else {
                panic!("challenge state required");
            };
            run_secret_text_frame(&context, id, &mut words[0], true, 0.0, Vec::new());
            run_secret_text_frame(
                &context,
                id,
                &mut words[0],
                false,
                0.1,
                vec![egui::Event::Text("undomark".to_owned())],
            );
            run_secret_text_frame(&context, id, &mut words[0], false, 1.2, Vec::new());
            assert_eq!(words[0].len(), 8);

            match transition {
                0 => app.cancel_generated_wallet(),
                1 => assert!(app.handle_secret_hold_outcome(
                    HoldOutcome::Triggered,
                    super::SecretHoldAction::ConfirmGeneratedBackup,
                )),
                2 => app.request_lock(super::LockReason::Explicit),
                _ => unreachable!(),
            }
            app.purge_queued_secret_text_edit_state(&context);
            assert!(egui::widgets::text_edit::TextEditState::load(&context, id).is_none());

            let mut recreated = String::new();
            run_secret_text_frame(&context, id, &mut recreated, true, 2.0, Vec::new());
            run_secret_text_frame(
                &context,
                id,
                &mut recreated,
                false,
                2.1,
                vec![undo_key_event()],
            );
            assert!(recreated.is_empty());
        }
    }

    #[test]
    fn session_scrub_purges_all_fifteen_explicit_text_states_and_financial_undo() {
        let context = egui::Context::default();
        let ids = super::secret_text_edit_ids();
        let mut unique = std::collections::HashSet::new();
        assert_eq!(ids.len(), 15);
        assert!(ids.iter().all(|id| unique.insert(*id)));
        for id in ids {
            egui::widgets::text_edit::TextEditState::default().store(&context, id);
        }
        super::purge_secret_text_edit_state(&context);
        assert!(
            ids.iter().all(|id| {
                egui::widgets::text_edit::TextEditState::load(&context, *id).is_none()
            })
        );

        let (commands, _command_receiver) = std::sync::mpsc::channel();
        let (_event_sender, events) = std::sync::mpsc::channel();
        let mut app = test_app(commands, events);
        let amount_id = super::amount_eth_text_edit_id();
        run_secret_text_frame(
            &context,
            amount_id,
            &mut app.amount_eth,
            true,
            3.0,
            Vec::new(),
        );
        run_secret_text_frame(
            &context,
            amount_id,
            &mut app.amount_eth,
            false,
            3.1,
            vec![egui::Event::Text("12345678".to_owned())],
        );
        run_secret_text_frame(
            &context,
            amount_id,
            &mut app.amount_eth,
            false,
            4.2,
            Vec::new(),
        );
        assert_eq!(app.amount_eth.len(), 8);
        app.request_lock(super::LockReason::Explicit);
        app.purge_queued_secret_text_edit_state(&context);
        assert!(app.amount_eth.is_empty());

        let mut recreated = String::new();
        run_secret_text_frame(&context, amount_id, &mut recreated, true, 5.0, Vec::new());
        run_secret_text_frame(
            &context,
            amount_id,
            &mut recreated,
            false,
            5.1,
            vec![undo_key_event()],
        );
        assert!(recreated.is_empty());
    }

    #[test]
    fn asset_identity_changes_purge_amount_and_egui_undo_for_token_or_native() {
        let context = egui::Context::default();
        let (commands, _command_receiver) = std::sync::mpsc::channel();
        let (_event_sender, events) = std::sync::mpsc::channel();
        let mut app = test_app(commands, events);
        let amount_id = super::amount_eth_text_edit_id();
        let token_a = super::headless_token_snapshot();
        let token_b = CustomTokenSnapshot {
            contract_address: "0x2222222222222222222222222222222222222222".to_owned(),
            state: CustomTokenState::Verified {
                symbol: Some("OTHER".to_owned()),
                decimals: 6,
                balance: "9.5".to_owned(),
            },
        };
        app.custom_tokens = vec![token_a.clone(), token_b.clone()];
        app.transfer_asset = TransferAssetChoice::SavedErc20 {
            contract_address: token_a.contract_address,
        };

        run_secret_text_frame(
            &context,
            amount_id,
            &mut app.amount_eth,
            true,
            0.0,
            Vec::new(),
        );
        run_secret_text_frame(
            &context,
            amount_id,
            &mut app.amount_eth,
            false,
            0.1,
            vec![egui::Event::Text("1.25".to_owned())],
        );
        run_secret_text_frame(
            &context,
            amount_id,
            &mut app.amount_eth,
            false,
            1.2,
            Vec::new(),
        );
        assert_eq!(app.amount_eth, "1.25");

        app.transfer_asset = TransferAssetChoice::SavedErc20 {
            contract_address: token_b.contract_address,
        };
        super::clear_transfer_amount_after_asset_change(
            &mut app.prepared,
            &mut app.hold,
            &mut app.amount_eth,
            &mut app.secret_text_state_purge_pending,
        );
        app.purge_queued_secret_text_edit_state(&context);
        run_secret_text_frame(
            &context,
            amount_id,
            &mut app.amount_eth,
            true,
            2.0,
            vec![undo_key_event()],
        );
        assert!(
            app.amount_eth.is_empty(),
            "token A amount must not survive token B selection"
        );

        run_secret_text_frame(
            &context,
            amount_id,
            &mut app.amount_eth,
            true,
            3.0,
            Vec::new(),
        );
        run_secret_text_frame(
            &context,
            amount_id,
            &mut app.amount_eth,
            false,
            3.1,
            vec![egui::Event::Text("250000".to_owned())],
        );
        run_secret_text_frame(
            &context,
            amount_id,
            &mut app.amount_eth,
            false,
            4.2,
            Vec::new(),
        );
        assert_eq!(app.amount_eth, "250000");

        app.transfer_asset = TransferAssetChoice::Native;
        super::clear_transfer_amount_after_asset_change(
            &mut app.prepared,
            &mut app.hold,
            &mut app.amount_eth,
            &mut app.secret_text_state_purge_pending,
        );
        app.purge_queued_secret_text_edit_state(&context);
        run_secret_text_frame(
            &context,
            amount_id,
            &mut app.amount_eth,
            true,
            5.0,
            vec![undo_key_event()],
        );
        assert!(
            app.amount_eth.is_empty(),
            "token amount must not survive native selection"
        );
    }

    #[test]
    fn token_refresh_forces_native_empty_amount_and_clears_preview_and_hold() {
        let (commands, _command_receiver) = std::sync::mpsc::channel();
        let (_event_sender, events) = std::sync::mpsc::channel();
        let mut app = test_app(commands, events);
        let token = super::headless_token_snapshot();
        app.custom_tokens = vec![token.clone()];
        app.transfer_asset = TransferAssetChoice::SavedErc20 {
            contract_address: token.contract_address.clone(),
        };
        app.amount_eth = "7.5".to_owned();
        app.prepared = Some(PreparedPreview::SavedErc20(super::headless_erc20_preview()));
        let started_at = Instant::now();
        assert!(matches!(
            app.hold.update(started_at, pressed_hold_input(true)),
            HoldOutcome::Holding(_)
        ));

        app.apply_worker_event(WorkerEvent::CustomTokensRefreshed(Ok(vec![token])));

        assert!(app.transfer_asset == TransferAssetChoice::Native);
        assert!(app.amount_eth.is_empty());
        assert!(app.prepared.is_none());
        assert!(app.hold.started_at.is_none());
        assert!(app.secret_text_state_purge_pending);
    }

    #[test]
    fn erc20_success_purges_amount_undo_and_invalidates_token_and_eth_snapshots() {
        let context = egui::Context::default();
        let (commands, _command_receiver) = std::sync::mpsc::channel();
        let (_event_sender, events) = std::sync::mpsc::channel();
        let mut app = test_app(commands, events);
        let token = super::headless_token_snapshot();
        app.custom_tokens = vec![token.clone()];
        app.transfer_asset = TransferAssetChoice::SavedErc20 {
            contract_address: token.contract_address,
        };
        app.prepared = Some(PreparedPreview::SavedErc20(super::headless_erc20_preview()));
        app.recipient = "0x3333333333333333333333333333333333333333".to_owned();
        let amount_id = super::amount_eth_text_edit_id();
        run_secret_text_frame(
            &context,
            amount_id,
            &mut app.amount_eth,
            true,
            0.0,
            Vec::new(),
        );
        run_secret_text_frame(
            &context,
            amount_id,
            &mut app.amount_eth,
            false,
            0.1,
            vec![egui::Event::Text("12.5".to_owned())],
        );
        run_secret_text_frame(
            &context,
            amount_id,
            &mut app.amount_eth,
            false,
            1.2,
            Vec::new(),
        );

        app.apply_worker_event(WorkerEvent::PreparedConfirmed(Ok(SendReceipt {
            transaction_hash: "confirmed-token-transaction".to_owned(),
        })));
        app.purge_queued_secret_text_edit_state(&context);

        assert!(app.transfer_asset == TransferAssetChoice::Native);
        assert!(app.prepared.is_none());
        assert!(app.recipient.is_empty());
        assert!(app.amount_eth.is_empty());
        assert!(app.custom_tokens.is_empty());
        assert_eq!(
            app.snapshot
                .as_ref()
                .map(|snapshot| snapshot.balance_eth.as_str()),
            Some("다시 조회 필요")
        );
        run_secret_text_frame(
            &context,
            amount_id,
            &mut app.amount_eth,
            true,
            2.0,
            vec![undo_key_event()],
        );
        assert!(
            app.amount_eth.is_empty(),
            "sent token amount must not be restorable"
        );
    }

    #[test]
    fn erc20_prepare_or_confirm_failure_discards_stale_token_state() {
        for confirm_failure in [false, true] {
            let (commands, _command_receiver) = std::sync::mpsc::channel();
            let (_event_sender, events) = std::sync::mpsc::channel();
            let mut app = test_app(commands, events);
            let token = super::headless_token_snapshot();
            app.custom_tokens = vec![token.clone()];
            app.transfer_asset = TransferAssetChoice::SavedErc20 {
                contract_address: token.contract_address,
            };
            app.amount_eth = "4.5".to_owned();
            if confirm_failure {
                app.prepared = Some(PreparedPreview::SavedErc20(super::headless_erc20_preview()));
                app.apply_worker_event(WorkerEvent::PreparedConfirmed(Err(
                    "준비된 거래의 안전 검증에 실패했습니다.".to_owned(),
                )));
            } else {
                app.apply_worker_event(WorkerEvent::SavedErc20TransferPrepared(Box::new(Err(
                    "토큰 컨트랙트 정보가 준비 중 변경되었습니다.".to_owned(),
                ))));
            }
            assert!(app.custom_tokens.is_empty());
            assert!(app.transfer_asset == TransferAssetChoice::Native);
            assert!(app.amount_eth.is_empty());
            assert!(app.prepared.is_none());
            assert!(app.hold.started_at.is_none());
            assert!(app.secret_text_state_purge_pending);
            if confirm_failure {
                assert_eq!(
                    app.snapshot
                        .as_ref()
                        .map(|snapshot| snapshot.balance_eth.as_str()),
                    Some("다시 조회 필요")
                );
            }
        }
    }

    #[test]
    fn native_confirm_failure_invalidates_eth_snapshot_and_preserves_ui_categories() {
        let (commands, _command_receiver) = std::sync::mpsc::channel();
        let (_event_sender, events) = std::sync::mpsc::channel();
        let mut app = test_app(commands, events);
        let prior_notice = "기존 안내는 오류 범주와 별개입니다.";
        let broadcast_unknown = "거래 전송 상태가 불확실합니다. 잠시 후 잔액을 확인해 주세요.";
        app.notice = Some(prior_notice.to_owned());
        app.prepared = Some(PreparedPreview::Native(exact_preview()));

        app.apply_worker_event(WorkerEvent::PreparedConfirmed(Err(
            broadcast_unknown.to_owned()
        )));

        assert!(app.prepared.is_none());
        assert_eq!(
            app.snapshot
                .as_ref()
                .map(|snapshot| snapshot.balance_eth.as_str()),
            Some("다시 조회 필요")
        );
        assert_eq!(app.notice.as_deref(), Some(prior_notice));
        assert_eq!(app.error.as_deref(), Some(broadcast_unknown));
    }

    #[test]
    fn exact_pending_retry_success_invalidates_all_rendered_balances() {
        let (commands, _command_receiver) = std::sync::mpsc::channel();
        let (_event_sender, events) = std::sync::mpsc::channel();
        let mut app = test_app(commands, events);
        app.custom_tokens = vec![super::headless_token_snapshot()];

        app.apply_worker_event(WorkerEvent::Retried(Ok(SendReceipt {
            transaction_hash: "retried-transaction".to_owned(),
        })));

        assert!(app.custom_tokens.is_empty());
        assert_eq!(
            app.snapshot
                .as_ref()
                .map(|snapshot| snapshot.balance_eth.as_str()),
            Some("다시 조회 필요")
        );
    }

    #[test]
    fn exact_pending_retry_failure_invalidates_all_balances_asset_and_amount_undo() {
        let context = egui::Context::default();
        let (commands, _command_receiver) = std::sync::mpsc::channel();
        let (_event_sender, events) = std::sync::mpsc::channel();
        let mut app = test_app(commands, events);
        let token = super::headless_token_snapshot();
        app.custom_tokens = vec![token.clone()];
        app.transfer_asset = TransferAssetChoice::SavedErc20 {
            contract_address: token.contract_address,
        };
        let prior_notice = "기존 retry 안내입니다.";
        let broadcast_unknown = "거래 전송 상태가 불확실합니다. 잠시 후 잔액을 확인해 주세요.";
        app.notice = Some(prior_notice.to_owned());
        let amount_id = super::amount_eth_text_edit_id();
        run_secret_text_frame(
            &context,
            amount_id,
            &mut app.amount_eth,
            true,
            0.0,
            Vec::new(),
        );
        run_secret_text_frame(
            &context,
            amount_id,
            &mut app.amount_eth,
            false,
            0.1,
            vec![egui::Event::Text("3.25".to_owned())],
        );
        run_secret_text_frame(
            &context,
            amount_id,
            &mut app.amount_eth,
            false,
            1.2,
            Vec::new(),
        );

        app.apply_worker_event(WorkerEvent::Retried(Err(broadcast_unknown.to_owned())));

        assert!(app.transfer_asset == TransferAssetChoice::Native);
        assert!(app.custom_tokens.is_empty());
        assert!(app.amount_eth.is_empty());
        assert_eq!(
            app.snapshot
                .as_ref()
                .map(|snapshot| snapshot.balance_eth.as_str()),
            Some("다시 조회 필요")
        );
        assert_eq!(app.notice.as_deref(), Some(prior_notice));
        assert_eq!(app.error.as_deref(), Some(broadcast_unknown));
        assert!(app.secret_text_state_purge_pending);
        app.purge_queued_secret_text_edit_state(&context);
        run_secret_text_frame(
            &context,
            amount_id,
            &mut app.amount_eth,
            true,
            2.0,
            vec![undo_key_event()],
        );
        assert!(
            app.amount_eth.is_empty(),
            "failed retry amount must not be restorable under native ETH"
        );
    }

    #[test]
    fn secret_export_handler_is_exactly_once_while_pending() {
        let (commands, command_receiver) = std::sync::mpsc::channel();
        let (_event_sender, events) = std::sync::mpsc::channel();
        let mut app = test_app(commands, events);
        app.reauth_password = "headless export password".to_owned();
        app.prepared = Some(PreparedPreview::Native(exact_preview()));
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
            Ok(super::WorkerRequest {
                command: WorkerCommand::ExportMnemonic { .. },
                ..
            })
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
        app.prepared = Some(PreparedPreview::Native(exact_preview()));
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
        let mut prepared = Some(PreparedPreview::Native(exact_preview()));
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
        revoke_during_open: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
        revoke_during_export: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
        revoke_during_confirm: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    }

    impl WalletBackend for RecordingBackend {
        fn lock_wallet(&mut self) {
            self.calls.push("lock");
        }

        fn open_wallet(&mut self, _input: &str) -> Result<WalletSnapshot, String> {
            self.calls.push("open");
            if let Some(epoch) = &self.revoke_during_open {
                epoch.store(1, std::sync::atomic::Ordering::SeqCst);
                Ok(super::headless_snapshot(
                    super::WalletKind::LegacyV1RawPrivateKey,
                ))
            } else {
                Err("unused".to_owned())
            }
        }

        fn export_mnemonic(
            &mut self,
            _password: super::SensitiveText,
        ) -> Result<super::SecretReveal, String> {
            self.calls.push("export");
            if let Some(epoch) = &self.revoke_during_export {
                epoch.store(1, std::sync::atomic::Ordering::SeqCst);
                Ok(super::headless_reveal(super::SecretRevealKind::Mnemonic))
            } else {
                Err("unused".to_owned())
            }
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

        fn confirm_prepared(
            &mut self,
            _permit: &super::SessionPermit<'_>,
        ) -> Result<SendReceipt, String> {
            self.calls.push("confirm");
            if let Some(epoch) = &self.revoke_during_confirm {
                epoch.store(1, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(SendReceipt {
                transaction_hash: "exact hash".to_owned(),
            })
        }

        fn cancel_prepared(&mut self) -> Result<(), String> {
            self.calls.push("cancel");
            Ok(())
        }

        fn retry_pending(
            &mut self,
            _permit: &super::SessionPermit<'_>,
        ) -> Result<SendReceipt, String> {
            self.calls.push("retry");
            Ok(SendReceipt {
                transaction_hash: "retry hash".to_owned(),
            })
        }
    }

    #[test]
    fn worker_routes_prepare_confirm_cancel_and_retry_exactly() {
        let mut backend = RecordingBackend::default();
        let active_epoch = std::sync::atomic::AtomicU64::new(0);
        let permit = super::SessionPermit::for_worker(0, &active_epoch);
        let event = execute_worker_command(
            &mut backend,
            WorkerCommand::PrepareTransfer {
                recipient: "exact recipient".to_owned(),
                amount_eth: "exact amount".to_owned(),
                fee_selection: FeeSelection::Faster,
            },
            &permit,
        );
        let WorkerEvent::TransferPrepared(result) = event else {
            panic!("prepare command must produce a preview event");
        };
        let preview = (*result).expect("faster preview");
        assert!(preview == faster_preview());
        assert!(matches!(
            execute_worker_command(&mut backend, WorkerCommand::ConfirmPrepared, &permit),
            WorkerEvent::PreparedConfirmed(Ok(_))
        ));
        assert!(matches!(
            execute_worker_command(&mut backend, WorkerCommand::CancelPrepared, &permit),
            WorkerEvent::PreparedCancelled(Ok(()))
        ));
        assert!(matches!(
            execute_worker_command(&mut backend, WorkerCommand::RetryPending, &permit),
            WorkerEvent::Retried(Ok(_))
        ));
        assert_eq!(backend.calls, ["prepare", "confirm", "cancel", "retry"]);
    }

    #[test]
    fn worker_drops_queued_stale_commands_before_backend_execution() {
        let active_epoch = std::sync::atomic::AtomicU64::new(1);
        let mut backend = RecordingBackend::default();
        let response = execute_worker_request(
            &mut backend,
            super::WorkerRequest {
                epoch: 0,
                command: WorkerCommand::ConfirmPrepared,
            },
            &active_epoch,
        );
        assert!(response.is_none());
        assert_eq!(backend.calls, ["lock"]);
    }

    #[test]
    fn worker_drops_open_secret_and_confirm_results_revoked_during_execution() {
        let open_epoch = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut open_backend = RecordingBackend {
            revoke_during_open: Some(std::sync::Arc::clone(&open_epoch)),
            ..Default::default()
        };
        let response = execute_worker_request(
            &mut open_backend,
            super::WorkerRequest {
                epoch: 0,
                command: WorkerCommand::Open {
                    password: zeroize::Zeroizing::new("headless-open-password".to_owned()),
                },
            },
            open_epoch.as_ref(),
        );
        assert!(response.is_none());
        assert_eq!(open_backend.calls, ["open", "lock"]);

        let export_epoch = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut export_backend = RecordingBackend {
            revoke_during_export: Some(std::sync::Arc::clone(&export_epoch)),
            ..Default::default()
        };
        let response = execute_worker_request(
            &mut export_backend,
            super::WorkerRequest {
                epoch: 0,
                command: WorkerCommand::ExportMnemonic {
                    password: super::SensitiveText::new("headless-export-password".to_owned()),
                },
            },
            export_epoch.as_ref(),
        );
        assert!(response.is_none());
        assert_eq!(export_backend.calls, ["export", "lock"]);

        let confirm_epoch = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut confirm_backend = RecordingBackend {
            revoke_during_confirm: Some(std::sync::Arc::clone(&confirm_epoch)),
            ..Default::default()
        };
        let response = execute_worker_request(
            &mut confirm_backend,
            super::WorkerRequest {
                epoch: 0,
                command: WorkerCommand::ConfirmPrepared,
            },
            confirm_epoch.as_ref(),
        );
        assert!(response.is_none());
        assert_eq!(confirm_backend.calls, ["confirm", "lock"]);
    }

    #[test]
    fn ui_reducer_ignores_a_stale_unlocked_response() {
        let (commands, _command_receiver) = std::sync::mpsc::channel();
        let (event_sender, events) = std::sync::mpsc::channel();
        let mut app = test_app(commands, events);
        app.scrub_frontend_session();
        app.session_epoch = 1;
        app.active_epoch
            .store(1, std::sync::atomic::Ordering::SeqCst);
        app.session_phase = super::SessionPhase::Locked;
        event_sender
            .send(super::WorkerResponse {
                epoch: 0,
                event: WorkerEvent::Opened(Ok(super::headless_snapshot(
                    super::WalletKind::LegacyV1RawPrivateKey,
                ))),
            })
            .expect("send stale response");
        app.process_events();
        assert!(app.snapshot.is_none());
        assert_eq!(app.session_phase, super::SessionPhase::Locked);
    }

    #[test]
    fn headless_smoke_exercises_button_handlers_and_state_reducer() -> Result<(), ()> {
        let evidence = run_headless_smoke()?;
        assert_eq!(evidence.transitions_checked, 74);
        assert_eq!(evidence.backend_routes_checked, 26);
        Ok(())
    }
}
