//! Secret-bearing backend for the standalone Sepolia development wallet.
//!
//! This module is deliberately independent from the production vault and
//! authorization formats. It supports one fixed testnet, a v2 mnemonic/raw-key
//! vault with a guarded legacy-v1 migration path, and native EIP-1559 transfers.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::Sha256;
use sha3::{Digest as _, Keccak256};
#[cfg(windows)]
use windows::Win32::Foundation::{GENERIC_WRITE, HANDLE};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FlushFileBuffers, OPEN_EXISTING,
};
#[cfg(windows)]
use windows::core::PCWSTR;
use zeroize::{Zeroize, Zeroizing};

use crate::rpc;
use crate::ui::{
    FeeSelection, NewMnemonicWords, SecretReveal, SecretRevealKind, SendReceipt, SensitiveText,
    TransferPreview, WalletBackend, WalletKind, WalletSnapshot,
};
use crate::vault_v2::{
    OpenedVaultV2, VaultCreationMetadata, VaultError, VaultOrigin, VaultPassword, open_vault_v2,
    seal_vault_v2,
};
use crate::wallet_secret::{
    MnemonicWordCount, SecretError, SecretExport, SecretExportKind, SecretInput, WalletSecret,
    WalletSource,
};

const NATIVE_TRANSFER_GAS: u64 = 21_000;
const MAX_TRANSFER_WEI: u64 = 10_000_000_000_000_000_000;
const MAX_PRIORITY_FEE_PER_GAS: u64 = 10_000_000_000;
const MAX_FEE_PER_GAS: u64 = 100_000_000_000;
const FEE_QUOTE_TTL: Duration = Duration::from_secs(60);
const MIN_CONFIRMABLE_QUOTE_SECONDS: u64 = 3;
const MAX_GWEI_INPUT_BYTES: usize = 32;
const GENERATED_BACKUP_TTL: Duration = Duration::from_secs(30);
const MAX_V2_VAULT_BYTES: usize = 4_096;

const VAULT_MAGIC: &[u8; 8] = b"YWSPV001";
const VAULT_VERSION: u16 = 1;
const VAULT_HEADER_BYTES: usize = 96;
const VAULT_HEADER_BYTES_U16: u16 = 96;
const VAULT_PASSWORD_PROFILE: u16 = 1;
const VAULT_KDF_ARGON2ID: u16 = 1;
const VAULT_AEAD_XCHACHA20_POLY1305: u16 = 1;
const VAULT_PAYLOAD_RAW_KEY: u16 = 1;
const ARGON2_MEMORY_KIB: u32 = 262_144;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const KEY_BYTES: usize = 32;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const AEAD_TAG_BYTES: usize = 16;
const VAULT_CIPHERTEXT_BYTES: usize = KEY_BYTES + AEAD_TAG_BYTES;
const VAULT_FILE_BYTES: usize = VAULT_HEADER_BYTES + VAULT_CIPHERTEXT_BYTES;
const HKDF_DOMAIN: &[u8] = b"your-wallet/sepolia-demo/v1";
const MINIMUM_PASSWORD_BYTES: usize = 12;
const MAXIMUM_PASSWORD_BYTES: usize = 1_024;
const PENDING_MAGIC: &[u8; 8] = b"YWSPS001";
const PENDING_VERSION: u16 = 1;
const PENDING_HEADER_BYTES: usize = 56;
const PENDING_HEADER_BYTES_U16: u16 = 56;
const MAX_PENDING_RAW_BYTES: usize = 512;

/// Concrete backend used by the native UI.
///
/// It intentionally has no `Debug` implementation because it owns the unlocked
/// private key and a local vault path.
pub struct DemoBackend {
    /// Legacy v1 path retained solely for authenticated migration/open.
    vault_path: PathBuf,
    vault_v2_path: PathBuf,
    pending_path: PathBuf,
    rpc: Box<dyn RpcAccess>,
    unlocked: Option<UnlockedWallet>,
    pending_generation: Option<PendingGeneratedWallet>,
    last_balance: Option<Word>,
    prepared: Option<PreparedTransfer>,
    clock: Box<dyn MonotonicClock>,
    #[cfg(test)]
    sign_attempts: usize,
}

enum UnlockedWallet {
    LegacyV1 {
        private_key: Zeroizing<[u8; KEY_BYTES]>,
        address: [u8; 20],
    },
    V2(OpenedVaultV2),
}

struct PendingGeneratedWallet {
    wallet: WalletSecret,
    password: VaultPassword,
    expires_at: Instant,
}

impl UnlockedWallet {
    fn validated_metadata(&self) -> Result<([u8; 20], WalletKind, u8), BackendError> {
        match self {
            Self::LegacyV1 { address, .. } => Ok((*address, WalletKind::LegacyV1RawPrivateKey, 1)),
            Self::V2(opened) => validated_wallet_metadata(opened.wallet()),
        }
    }

    #[cfg(test)]
    fn legacy_private_key_for_test(&self) -> &[u8; KEY_BYTES] {
        match self {
            Self::LegacyV1 { private_key, .. } => private_key,
            Self::V2(_) => panic!("test expected a legacy v1 wallet"),
        }
    }
}

/// Exact, signer-ready Sepolia fields fixed at preview time.
///
/// This value is neither `Clone` nor public. Confirmation consumes it before
/// any private-key operation, so edited UI strings cannot alter signed fields.
struct PreparedTransfer {
    sender: [u8; 20],
    recipient: [u8; 20],
    value: Word,
    nonce: Word,
    gas_limit: Word,
    quoted_base_fee: Word,
    priority_fee: Word,
    maximum_fee: Word,
    estimated_network_fee: Word,
    maximum_network_fee: Word,
    estimated_spend: Word,
    maximum_spend: Word,
    quote_expires_at: Instant,
}

#[derive(Clone, Copy)]
struct NetworkFeeQuote {
    base_fee: Word,
    recommended_priority_fee: Word,
    recommended_maximum_fee: Word,
}

#[derive(Clone, Copy)]
struct FrozenFeePlan {
    mode_label: &'static str,
    quoted_base_fee: Word,
    priority_fee: Word,
    maximum_fee: Word,
}

trait MonotonicClock: Send {
    fn now(&self) -> Instant;
}

struct SystemClock;

impl MonotonicClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

trait RpcAccess: Send {
    fn verify_sepolia(&self) -> Result<(), ()>;
    fn balance(&self, address: [u8; 20]) -> Result<Word, ()>;
    fn pending_balance(&self, address: [u8; 20]) -> Result<Word, ()>;
    fn pending_nonce(&self, address: [u8; 20]) -> Result<Word, ()>;
    fn fee_quote(&self) -> Result<NetworkFeeQuote, ()>;
    fn latest_base_fee(&self) -> Result<Word, ()>;
    #[allow(clippy::too_many_arguments)]
    fn estimate_native_transfer_gas(
        &self,
        sender: [u8; 20],
        recipient: [u8; 20],
        value: Word,
        nonce: Word,
        priority_fee: Word,
        maximum_fee: Word,
    ) -> Result<Word, ()>;
    fn send_raw_transaction(&self, signed: &[u8]) -> Result<[u8; 32], ()>;
}

impl DemoBackend {
    /// Constructs the fixed-endpoint Sepolia backend without touching the vault.
    pub fn new() -> Result<Self, String> {
        let local_data = std::env::var_os("LOCALAPPDATA")
            .ok_or_else(|| error_text(BackendError::StorageUnavailable))?;
        let vault_directory = PathBuf::from(local_data)
            .join("YourWallet")
            .join("SepoliaDemo");
        let vault_path = vault_directory.join("vault-v1.bin");
        let vault_v2_path = vault_directory.join("vault-v2.bin");
        let pending_path = sibling_pending_path(&vault_path)?;
        let rpc = rpc::SepoliaRpc::new();
        Ok(Self {
            vault_path,
            vault_v2_path,
            pending_path,
            rpc: Box::new(LiveRpc(rpc)),
            unlocked: None,
            pending_generation: None,
            last_balance: None,
            prepared: None,
            clock: Box::new(SystemClock),
            #[cfg(test)]
            sign_attempts: 0,
        })
    }

    #[cfg(test)]
    fn with_rpc(vault_path: PathBuf, rpc: impl RpcAccess + 'static) -> Self {
        let pending_path = vault_path.with_file_name("pending-v1.bin");
        let vault_v2_path = vault_path.with_file_name("vault-v2.bin");
        Self {
            vault_path,
            vault_v2_path,
            pending_path,
            rpc: Box::new(rpc),
            unlocked: None,
            pending_generation: None,
            last_balance: None,
            prepared: None,
            clock: Box::new(SystemClock),
            sign_attempts: 0,
        }
    }

    #[cfg(test)]
    fn with_rpc_and_clock(
        vault_path: PathBuf,
        rpc: impl RpcAccess + 'static,
        clock: impl MonotonicClock + 'static,
    ) -> Self {
        let mut backend = Self::with_rpc(vault_path, rpc);
        backend.clock = Box::new(clock);
        backend
    }

    /// Returns whether the separate disposable testnet vault exists.
    #[must_use]
    pub fn wallet_exists(&self) -> bool {
        path_may_exist(&self.vault_v2_path) || path_may_exist(&self.vault_path)
    }

    /// Reports a prior signed transaction whose broadcast result was not
    /// durably resolved. A new transaction is never signed while this is true.
    #[must_use]
    pub fn pending_broadcast_exists(&self) -> bool {
        path_may_exist(&self.pending_path)
    }

    /// Immediately forgets the unlocked key and cached balance.
    #[cfg(test)]
    pub fn lock(&mut self) {
        self.prepared = None;
        self.pending_generation = None;
        self.unlocked = None;
        self.last_balance = None;
    }

    /// Returns the current public address, if the vault is unlocked.
    #[must_use]
    #[cfg(test)]
    pub fn address(&self) -> Option<String> {
        self.unlocked
            .as_ref()
            .and_then(|wallet| wallet.validated_metadata().ok())
            .map(|(address, _, _)| checksum_address(address))
    }

    /// Retries exactly the previously persisted signed transaction bytes.
    ///
    /// This never creates a new signature or nonce. The pending record remains
    /// on every error or hash mismatch and is deleted only after an exact hash
    /// match from the pinned Sepolia endpoint.
    pub fn retry_pending(&mut self) -> Result<SendReceipt, String> {
        self.retry_pending_inner().map_err(error_text)
    }

    fn snapshot(&self) -> Result<WalletSnapshot, BackendError> {
        let wallet = self.unlocked.as_ref().ok_or(BackendError::Locked)?;
        let (address, wallet_kind, account_count) = wallet.validated_metadata()?;
        let balance_eth = self
            .last_balance
            .map_or_else(|| "조회 전".to_owned(), format_ether);
        Ok(WalletSnapshot {
            address: checksum_address(address),
            balance_eth,
            wallet_kind,
            account_count,
        })
    }

    #[cfg(test)]
    fn create(&mut self, password: &str) -> Result<WalletSnapshot, BackendError> {
        self.prepared = None;
        validate_password(password)?;
        if self.wallet_exists() {
            return Err(BackendError::AlreadyExists);
        }

        let private_key = generate_private_key()?;
        let address = address_from_private_key(&private_key)?;
        let vault = seal_vault(&private_key, password)?;
        write_new_vault(&self.vault_path, vault.as_slice())?;

        self.unlocked = Some(UnlockedWallet::LegacyV1 {
            private_key,
            address,
        });
        self.last_balance = Some(Word::ZERO);
        self.snapshot()
    }

    fn open(&mut self, password: &str) -> Result<WalletSnapshot, BackendError> {
        self.prepared = None;
        self.pending_generation = None;
        self.unlocked = None;
        self.last_balance = None;
        match fs::symlink_metadata(&self.vault_v2_path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() {
                    return Err(BackendError::VaultInvalid);
                }
                let password = VaultPassword::new(password.to_owned()).map_err(map_vault_error)?;
                let bytes = read_v2_vault(&self.vault_v2_path)?;
                let opened = open_vault_v2(bytes.as_slice(), &password).map_err(map_vault_error)?;
                validated_wallet_metadata(opened.wallet())?;
                self.unlocked = Some(UnlockedWallet::V2(opened));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                validate_password(password)?;
                let bytes = read_vault(&self.vault_path)?;
                let private_key = open_vault(bytes.as_slice(), password)?;
                let address = address_from_private_key(&private_key)?;
                self.unlocked = Some(UnlockedWallet::LegacyV1 {
                    private_key,
                    address,
                });
            }
            Err(_) => return Err(BackendError::StorageUnavailable),
        }
        self.snapshot()
    }

    fn begin_generate(
        &mut self,
        words: NewMnemonicWords,
        password: SensitiveText,
        password_confirmation: SensitiveText,
    ) -> Result<SecretReveal, BackendError> {
        self.prepared = None;
        self.ensure_management_mutation_allowed()?;
        if self.pending_generation.is_some() {
            return Err(BackendError::GenerationPending);
        }
        let password = matching_vault_password(password, password_confirmation)?;
        let word_count = match words {
            NewMnemonicWords::Twelve => MnemonicWordCount::Twelve,
            NewMnemonicWords::TwentyFour => MnemonicWordCount::TwentyFour,
        };
        let wallet = WalletSecret::generate_mnemonic(word_count).map_err(map_secret_error)?;
        let (_, kind, _) = validated_wallet_metadata(&wallet)?;
        if !matches!(
            kind,
            WalletKind::V2Mnemonic {
                word_count: 12 | 24
            }
        ) {
            return Err(BackendError::WalletMetadataInvalid);
        }
        let export = wallet.export_mnemonic().map_err(map_secret_error)?;
        let expires_at = self
            .clock
            .now()
            .checked_add(GENERATED_BACKUP_TTL)
            .ok_or(BackendError::GenerationExpired)?;
        self.pending_generation = Some(PendingGeneratedWallet {
            wallet,
            password,
            expires_at,
        });
        secret_reveal(export)
    }

    fn confirm_generated(&mut self) -> Result<WalletSnapshot, BackendError> {
        self.prepared = None;
        let pending = self
            .pending_generation
            .take()
            .ok_or(BackendError::NoPendingGeneration)?;
        if self.clock.now() >= pending.expires_at {
            return Err(BackendError::GenerationExpired);
        }
        self.ensure_management_mutation_allowed()?;
        self.persist_new_v2(
            pending.wallet,
            pending.password,
            VaultOrigin::GeneratedMnemonic,
        )
    }

    fn cancel_generated(&mut self) {
        self.pending_generation = None;
    }

    fn import_mnemonic(
        &mut self,
        mnemonic: SensitiveText,
        password: SensitiveText,
        password_confirmation: SensitiveText,
    ) -> Result<WalletSnapshot, BackendError> {
        self.prepared = None;
        self.ensure_management_mutation_allowed()?;
        if self.pending_generation.is_some() {
            return Err(BackendError::GenerationPending);
        }
        let password = matching_vault_password(password, password_confirmation)?;
        let wallet = WalletSecret::import_mnemonic(SecretInput::new(take_sensitive(mnemonic)))
            .map_err(map_secret_error)?;
        self.persist_new_v2(wallet, password, VaultOrigin::ImportedMnemonic)
    }

    fn import_private_key(
        &mut self,
        private_key: SensitiveText,
        password: SensitiveText,
        password_confirmation: SensitiveText,
    ) -> Result<WalletSnapshot, BackendError> {
        self.prepared = None;
        self.ensure_management_mutation_allowed()?;
        if self.pending_generation.is_some() {
            return Err(BackendError::GenerationPending);
        }
        let password = matching_vault_password(password, password_confirmation)?;
        let wallet =
            WalletSecret::import_raw_private_key(SecretInput::new(take_sensitive(private_key)))
                .map_err(map_secret_error)?;
        self.persist_new_v2(wallet, password, VaultOrigin::ImportedRawPrivateKey)
    }

    fn migrate_legacy(
        &mut self,
        old_password: SensitiveText,
        new_password: SensitiveText,
        new_password_confirmation: SensitiveText,
    ) -> Result<WalletSnapshot, BackendError> {
        self.prepared = None;
        if self.pending_broadcast_exists() {
            return Err(BackendError::PendingExists);
        }
        if self.pending_generation.is_some() {
            return Err(BackendError::GenerationPending);
        }
        if path_may_exist(&self.vault_v2_path) {
            return Err(BackendError::AlreadyExists);
        }
        if !path_may_exist(&self.vault_path) {
            return Err(BackendError::LegacyNotFound);
        }

        let old_password = take_sensitive_zeroizing(old_password);
        validate_password(old_password.as_str())?;
        let legacy_bytes = read_vault(&self.vault_path)?;
        let private_key = open_vault(legacy_bytes.as_slice(), old_password.as_str())?;
        let legacy_address = address_from_private_key(&private_key)?;
        let wallet =
            WalletSecret::from_raw_private_key_bytes(private_key).map_err(map_secret_error)?;
        let (migrated_address, kind, account_count) = validated_wallet_metadata(&wallet)?;
        if migrated_address != legacy_address
            || kind != WalletKind::V2RawPrivateKey
            || account_count != 1
        {
            return Err(BackendError::WalletMetadataInvalid);
        }
        let new_password = matching_vault_password(new_password, new_password_confirmation)?;
        let metadata = confirmed_metadata(VaultOrigin::MigratedV1RawPrivateKey)?;
        let sealed = seal_vault_v2(&wallet, &new_password, metadata).map_err(map_vault_error)?;
        let opened = open_vault_v2(sealed.as_bytes(), &new_password).map_err(map_vault_error)?;
        let (opened_address, _, _) = validated_wallet_metadata(opened.wallet())?;
        if opened_address != legacy_address {
            return Err(BackendError::WalletMetadataInvalid);
        }
        if self.pending_broadcast_exists() {
            return Err(BackendError::PendingExists);
        }
        if path_may_exist(&self.vault_v2_path) {
            return Err(BackendError::AlreadyExists);
        }
        write_new_file(&self.vault_v2_path, sealed.as_bytes())?;
        if remove_legacy_vault(&self.vault_path).is_err() {
            self.unlocked = None;
            self.last_balance = None;
            return Err(BackendError::MigrationCleanup);
        }
        self.unlocked = Some(UnlockedWallet::V2(opened));
        self.last_balance = None;
        self.snapshot()
    }

    fn export_mnemonic_inner(
        &mut self,
        password: SensitiveText,
    ) -> Result<SecretReveal, BackendError> {
        self.prepared = None;
        self.ensure_secret_export_allowed()?;
        let opened = self.reopen_authenticated_v2(password)?;
        if opened.wallet().source() != WalletSource::Mnemonic {
            return Err(BackendError::MnemonicUnavailable);
        }
        self.ensure_secret_export_allowed()?;
        secret_reveal(
            opened
                .wallet()
                .export_mnemonic()
                .map_err(map_secret_error)?,
        )
    }

    fn export_account_private_key_inner(
        &mut self,
        password: SensitiveText,
    ) -> Result<SecretReveal, BackendError> {
        self.prepared = None;
        self.ensure_secret_export_allowed()?;
        let export = match self.unlocked.as_ref().ok_or(BackendError::Locked)? {
            UnlockedWallet::V2(_) => {
                let opened = self.reopen_authenticated_v2(password)?;
                opened
                    .wallet()
                    .export_account_private_key(0)
                    .map_err(map_secret_error)?
            }
            UnlockedWallet::LegacyV1 {
                private_key,
                address,
            } => {
                let password = take_sensitive_zeroizing(password);
                validate_password(password.as_str())?;
                let bytes = read_vault(&self.vault_path)?;
                let reopened_key = open_vault(bytes.as_slice(), password.as_str())?;
                if address_from_private_key(&reopened_key)? != *address
                    || reopened_key.as_ref() != private_key.as_ref()
                {
                    return Err(BackendError::WalletChanged);
                }
                let wallet = WalletSecret::from_raw_private_key_bytes(reopened_key)
                    .map_err(map_secret_error)?;
                validated_wallet_metadata(&wallet)?;
                wallet
                    .export_account_private_key(0)
                    .map_err(map_secret_error)?
            }
        };
        self.ensure_secret_export_allowed()?;
        secret_reveal(export)
    }

    fn persist_new_v2(
        &mut self,
        wallet: WalletSecret,
        password: VaultPassword,
        origin: VaultOrigin,
    ) -> Result<WalletSnapshot, BackendError> {
        self.ensure_management_mutation_allowed()?;
        validated_wallet_metadata(&wallet)?;
        let metadata = confirmed_metadata(origin)?;
        let sealed = seal_vault_v2(&wallet, &password, metadata).map_err(map_vault_error)?;
        let opened = open_vault_v2(sealed.as_bytes(), &password).map_err(map_vault_error)?;
        validated_wallet_metadata(opened.wallet())?;
        self.ensure_management_mutation_allowed()?;
        write_new_file(&self.vault_v2_path, sealed.as_bytes())?;
        self.unlocked = Some(UnlockedWallet::V2(opened));
        self.last_balance = Some(Word::ZERO);
        self.snapshot()
    }

    fn ensure_management_mutation_allowed(&self) -> Result<(), BackendError> {
        if self.pending_broadcast_exists() {
            return Err(BackendError::PendingExists);
        }
        if self.wallet_exists() {
            return Err(BackendError::AlreadyExists);
        }
        Ok(())
    }

    fn ensure_secret_export_allowed(&self) -> Result<(), BackendError> {
        if self.pending_broadcast_exists() {
            return Err(BackendError::PendingExists);
        }
        if self.pending_generation.is_some() {
            return Err(BackendError::GenerationPending);
        }
        Ok(())
    }

    fn reopen_authenticated_v2(
        &self,
        password: SensitiveText,
    ) -> Result<OpenedVaultV2, BackendError> {
        let UnlockedWallet::V2(current) = self.unlocked.as_ref().ok_or(BackendError::Locked)?
        else {
            return Err(BackendError::MnemonicUnavailable);
        };
        let password = VaultPassword::new(take_sensitive(password)).map_err(map_vault_error)?;
        let bytes = read_v2_vault(&self.vault_v2_path)?;
        let reopened = open_vault_v2(bytes.as_slice(), &password).map_err(map_vault_error)?;
        let current_metadata = validated_wallet_metadata(current.wallet())?;
        let reopened_metadata = validated_wallet_metadata(reopened.wallet())?;
        if reopened.vault_id() != current.vault_id()
            || reopened.metadata() != current.metadata()
            || reopened_metadata != current_metadata
        {
            return Err(BackendError::WalletChanged);
        }
        Ok(reopened)
    }

    fn refresh_snapshot(&mut self) -> Result<WalletSnapshot, BackendError> {
        self.prepared = None;
        let (address, _, _) = self
            .unlocked
            .as_ref()
            .ok_or(BackendError::Locked)?
            .validated_metadata()?;
        self.rpc
            .verify_sepolia()
            .map_err(|()| BackendError::RpcUnavailable)?;
        let balance = self
            .rpc
            .balance(address)
            .map_err(|()| BackendError::BalanceUnavailable)?;
        self.last_balance = Some(balance);
        self.snapshot()
    }

    fn prepare_transfer_inner(
        &mut self,
        recipient: &str,
        amount_eth: &str,
        fee_selection: FeeSelection,
    ) -> Result<TransferPreview, BackendError> {
        // A second preparation invalidates the first before any fallible work.
        // Failed re-preparation therefore cannot leave a stale confirmation.
        self.prepared = None;
        let wallet = self.unlocked.as_ref().ok_or(BackendError::Locked)?;
        if self.pending_broadcast_exists() {
            return Err(BackendError::PendingExists);
        }
        let (sender, _, _) = wallet.validated_metadata()?;
        let recipient = parse_address(recipient)?;
        let value = parse_ether(amount_eth)?;
        if value.is_zero() {
            return Err(BackendError::InvalidAmount);
        }
        if value > Word::from_u64(MAX_TRANSFER_WEI) {
            return Err(BackendError::AmountLimit);
        }

        self.rpc
            .verify_sepolia()
            .map_err(|()| BackendError::RpcUnavailable)?;
        let nonce = self
            .rpc
            .pending_nonce(sender)
            .map_err(|()| BackendError::RpcUnavailable)?;
        let quote = self
            .rpc
            .fee_quote()
            .map_err(|()| BackendError::RpcUnavailable)?;
        let fee_plan = resolve_fee_plan(fee_selection, quote)?;
        let quote_expires_at = self
            .clock
            .now()
            .checked_add(FEE_QUOTE_TTL)
            .ok_or(BackendError::PreparedInvalid)?;
        let gas_limit = Word::from_u64(NATIVE_TRANSFER_GAS);
        let estimated_gas = self
            .rpc
            .estimate_native_transfer_gas(
                sender,
                recipient,
                value,
                nonce,
                fee_plan.priority_fee,
                fee_plan.maximum_fee,
            )
            .map_err(|()| BackendError::RpcUnavailable)?;
        if estimated_gas != gas_limit {
            return Err(BackendError::UnsupportedTransfer);
        }
        let balance = self
            .rpc
            .pending_balance(sender)
            .map_err(|()| BackendError::BalanceUnavailable)?;
        let estimated_gas_price = fee_plan
            .quoted_base_fee
            .checked_add(fee_plan.priority_fee)
            .ok_or(BackendError::FeeLimit)?;
        let estimated_network_fee = estimated_gas_price
            .checked_mul_u64(NATIVE_TRANSFER_GAS)
            .ok_or(BackendError::FeeLimit)?;
        let maximum_network_fee = fee_plan
            .maximum_fee
            .checked_mul_u64(NATIVE_TRANSFER_GAS)
            .ok_or(BackendError::FeeLimit)?;
        let estimated_spend = value
            .checked_add(estimated_network_fee)
            .ok_or(BackendError::FeeLimit)?;
        let maximum_spend = value
            .checked_add(maximum_network_fee)
            .ok_or(BackendError::FeeLimit)?;
        if maximum_spend > balance {
            return Err(BackendError::InsufficientBalance);
        }
        let remaining_quote_seconds =
            conservative_remaining_quote_seconds(self.clock.as_ref(), quote_expires_at)?;

        let preview = TransferPreview {
            recipient: checksum_address(recipient),
            amount_eth: format_ether(value),
            nonce: decimal_string(nonce),
            fee_mode_ko: fee_plan.mode_label.to_owned(),
            gas_limit: NATIVE_TRANSFER_GAS.to_string(),
            quoted_base_fee_per_gas_gwei: format_gwei(fee_plan.quoted_base_fee),
            max_priority_fee_per_gas_gwei: format_gwei(fee_plan.priority_fee),
            max_fee_per_gas_gwei: format_gwei(fee_plan.maximum_fee),
            estimated_network_fee_eth: format_ether(estimated_network_fee),
            max_network_fee_eth: format_ether(maximum_network_fee),
            estimated_total_eth: format_ether(estimated_spend),
            max_total_eth: format_ether(maximum_spend),
            quote_valid_for_seconds: remaining_quote_seconds.to_string(),
        };
        self.prepared = Some(PreparedTransfer {
            sender,
            recipient,
            value,
            nonce,
            gas_limit,
            quoted_base_fee: fee_plan.quoted_base_fee,
            priority_fee: fee_plan.priority_fee,
            maximum_fee: fee_plan.maximum_fee,
            estimated_network_fee,
            maximum_network_fee,
            estimated_spend,
            maximum_spend,
            quote_expires_at,
        });
        Ok(preview)
    }

    fn confirm_prepared_inner(&mut self) -> Result<SendReceipt, BackendError> {
        if self.pending_broadcast_exists() {
            self.prepared = None;
            return Err(BackendError::PendingExists);
        }
        let prepared = self
            .prepared
            .take()
            .ok_or(BackendError::NoPreparedTransfer)?;
        let wallet = self.unlocked.as_ref().ok_or(BackendError::Locked)?;
        let (wallet_address, _, _) = wallet.validated_metadata()?;
        let expected_estimated_gas_price =
            prepared.quoted_base_fee.checked_add(prepared.priority_fee);
        if wallet_address != prepared.sender
            || prepared.recipient == [0; 20]
            || prepared.value.is_zero()
            || prepared.value > Word::from_u64(MAX_TRANSFER_WEI)
            || prepared.gas_limit != Word::from_u64(NATIVE_TRANSFER_GAS)
            || validate_fee_values(
                prepared.quoted_base_fee,
                prepared.priority_fee,
                prepared.maximum_fee,
            )
            .is_err()
            || expected_estimated_gas_price
                .and_then(|price| price.checked_mul_u64(NATIVE_TRANSFER_GAS))
                != Some(prepared.estimated_network_fee)
            || prepared.maximum_fee.checked_mul_u64(NATIVE_TRANSFER_GAS)
                != Some(prepared.maximum_network_fee)
            || prepared.value.checked_add(prepared.estimated_network_fee)
                != Some(prepared.estimated_spend)
            || prepared.value.checked_add(prepared.maximum_network_fee)
                != Some(prepared.maximum_spend)
        {
            return Err(BackendError::PreparedInvalid);
        }
        ensure_quote_live(self.clock.as_ref(), prepared.quote_expires_at)?;
        self.rpc
            .verify_sepolia()
            .map_err(|()| BackendError::RpcUnavailable)?;
        let current_nonce = self
            .rpc
            .pending_nonce(prepared.sender)
            .map_err(|()| BackendError::RpcUnavailable)?;
        if current_nonce != prepared.nonce {
            return Err(BackendError::AccountChanged);
        }
        let current_base_fee = self
            .rpc
            .latest_base_fee()
            .map_err(|()| BackendError::RpcUnavailable)?;
        if validate_fee_values(
            current_base_fee,
            prepared.priority_fee,
            prepared.maximum_fee,
        )
        .is_err()
        {
            return Err(BackendError::QuoteChanged);
        }
        let balance = self
            .rpc
            .pending_balance(prepared.sender)
            .map_err(|()| BackendError::BalanceUnavailable)?;
        if prepared.maximum_spend > balance {
            return Err(BackendError::InsufficientBalance);
        }
        let estimated_gas = self
            .rpc
            .estimate_native_transfer_gas(
                prepared.sender,
                prepared.recipient,
                prepared.value,
                prepared.nonce,
                prepared.priority_fee,
                prepared.maximum_fee,
            )
            .map_err(|()| BackendError::RpcUnavailable)?;
        if estimated_gas != prepared.gas_limit {
            return Err(BackendError::UnsupportedTransfer);
        }
        ensure_quote_live(self.clock.as_ref(), prepared.quote_expires_at)?;
        #[cfg(test)]
        {
            self.sign_attempts += 1;
        }
        let signed = match wallet {
            UnlockedWallet::LegacyV1 { private_key, .. } => sign_native_type_two(
                private_key,
                prepared.sender,
                prepared.recipient,
                prepared.value,
                prepared.nonce,
                prepared.gas_limit,
                prepared.priority_fee,
                prepared.maximum_fee,
            )?,
            UnlockedWallet::V2(opened) => {
                let private_key = opened
                    .wallet()
                    .account_private_key(0)
                    .map_err(map_secret_error)?;
                sign_native_type_two(
                    private_key.as_bytes(),
                    prepared.sender,
                    prepared.recipient,
                    prepared.value,
                    prepared.nonce,
                    prepared.gas_limit,
                    prepared.priority_fee,
                    prepared.maximum_fee,
                )?
            }
        };
        write_new_pending(
            &self.pending_path,
            signed.transaction_hash,
            signed.bytes.as_slice(),
        )?;
        let returned_hash = self
            .rpc
            .send_raw_transaction(signed.bytes.as_slice())
            .map_err(|()| BackendError::BroadcastUnknown)?;
        if returned_hash != signed.transaction_hash {
            return Err(BackendError::HashMismatch);
        }
        remove_pending(&self.pending_path)?;
        self.last_balance = None;
        Ok(SendReceipt {
            transaction_hash: fixed_hex(&returned_hash),
        })
    }

    fn cancel_prepared_inner(&mut self) {
        self.prepared = None;
    }

    fn retry_pending_inner(&mut self) -> Result<SendReceipt, BackendError> {
        self.prepared = None;
        if self.unlocked.is_none() {
            return Err(BackendError::Locked);
        }
        let pending = read_pending(&self.pending_path)?;
        self.rpc
            .verify_sepolia()
            .map_err(|()| BackendError::RpcUnavailable)?;
        let returned_hash = self
            .rpc
            .send_raw_transaction(pending.raw_transaction.as_slice())
            .map_err(|()| BackendError::BroadcastUnknown)?;
        if returned_hash != pending.transaction_hash {
            return Err(BackendError::HashMismatch);
        }
        remove_pending(&self.pending_path)?;
        self.last_balance = None;
        Ok(SendReceipt {
            transaction_hash: fixed_hex(&returned_hash),
        })
    }
}

impl WalletBackend for DemoBackend {
    fn begin_generate_wallet(
        &mut self,
        words: NewMnemonicWords,
        password: SensitiveText,
        password_confirmation: SensitiveText,
    ) -> Result<SecretReveal, String> {
        self.begin_generate(words, password, password_confirmation)
            .map_err(error_text)
    }

    fn confirm_generated_wallet(&mut self) -> Result<WalletSnapshot, String> {
        self.confirm_generated().map_err(error_text)
    }

    fn cancel_generated_wallet(&mut self) -> Result<(), String> {
        self.cancel_generated();
        Ok(())
    }

    fn import_mnemonic_wallet(
        &mut self,
        mnemonic: SensitiveText,
        password: SensitiveText,
        password_confirmation: SensitiveText,
    ) -> Result<WalletSnapshot, String> {
        self.import_mnemonic(mnemonic, password, password_confirmation)
            .map_err(error_text)
    }

    fn import_private_key_wallet(
        &mut self,
        private_key: SensitiveText,
        password: SensitiveText,
        password_confirmation: SensitiveText,
    ) -> Result<WalletSnapshot, String> {
        self.import_private_key(private_key, password, password_confirmation)
            .map_err(error_text)
    }

    fn open_wallet(&mut self, password: &str) -> Result<WalletSnapshot, String> {
        self.open(password).map_err(error_text)
    }

    fn migrate_legacy_wallet(
        &mut self,
        old_password: SensitiveText,
        new_password: SensitiveText,
        new_password_confirmation: SensitiveText,
    ) -> Result<WalletSnapshot, String> {
        self.migrate_legacy(old_password, new_password, new_password_confirmation)
            .map_err(error_text)
    }

    fn export_mnemonic(&mut self, password: SensitiveText) -> Result<SecretReveal, String> {
        self.export_mnemonic_inner(password).map_err(error_text)
    }

    fn export_account_private_key(
        &mut self,
        password: SensitiveText,
    ) -> Result<SecretReveal, String> {
        self.export_account_private_key_inner(password)
            .map_err(error_text)
    }

    fn refresh(&mut self) -> Result<WalletSnapshot, String> {
        self.refresh_snapshot().map_err(error_text)
    }

    fn prepare_transfer(
        &mut self,
        recipient: &str,
        amount_eth: &str,
        fee_selection: FeeSelection,
    ) -> Result<TransferPreview, String> {
        self.prepare_transfer_inner(recipient, amount_eth, fee_selection)
            .map_err(error_text)
    }

    fn confirm_prepared(&mut self) -> Result<SendReceipt, String> {
        self.confirm_prepared_inner().map_err(error_text)
    }

    fn cancel_prepared(&mut self) -> Result<(), String> {
        self.cancel_prepared_inner();
        Ok(())
    }

    fn retry_pending(&mut self) -> Result<SendReceipt, String> {
        DemoBackend::retry_pending(self)
    }
}

/// Builds the boxed backend expected by the UI worker.
pub fn build_backend() -> Result<Box<dyn WalletBackend>, String> {
    DemoBackend::new().map(|backend| Box::new(backend) as Box<dyn WalletBackend>)
}

struct LiveRpc(rpc::SepoliaRpc);

impl RpcAccess for LiveRpc {
    fn verify_sepolia(&self) -> Result<(), ()> {
        self.0.verify_sepolia().map_err(|_| ())
    }

    fn balance(&self, address: [u8; 20]) -> Result<Word, ()> {
        self.0
            .balance(rpc::Address20::new(address))
            .map(|value| Word::from_be_bytes(*value.as_be_bytes()))
            .map_err(|_| ())
    }

    fn pending_balance(&self, address: [u8; 20]) -> Result<Word, ()> {
        self.0
            .pending_balance(rpc::Address20::new(address))
            .map(|value| Word::from_be_bytes(*value.as_be_bytes()))
            .map_err(|_| ())
    }

    fn pending_nonce(&self, address: [u8; 20]) -> Result<Word, ()> {
        self.0
            .pending_nonce(rpc::Address20::new(address))
            .map(|value| Word::from_be_bytes(*value.as_be_bytes()))
            .map_err(|_| ())
    }

    fn fee_quote(&self) -> Result<NetworkFeeQuote, ()> {
        self.0
            .fee_quote()
            .map(|quote| NetworkFeeQuote {
                base_fee: Word::from_be_bytes(*quote.base_fee_per_gas.as_be_bytes()),
                recommended_priority_fee: Word::from_be_bytes(
                    *quote.max_priority_fee_per_gas.as_be_bytes(),
                ),
                recommended_maximum_fee: Word::from_be_bytes(*quote.max_fee_per_gas.as_be_bytes()),
            })
            .map_err(|_| ())
    }

    fn latest_base_fee(&self) -> Result<Word, ()> {
        self.0
            .latest_base_fee()
            .map(|value| Word::from_be_bytes(*value.as_be_bytes()))
            .map_err(|_| ())
    }

    fn estimate_native_transfer_gas(
        &self,
        sender: [u8; 20],
        recipient: [u8; 20],
        value: Word,
        nonce: Word,
        priority_fee: Word,
        maximum_fee: Word,
    ) -> Result<Word, ()> {
        self.0
            .estimate_native_transfer_gas(
                rpc::Address20::new(sender),
                rpc::Address20::new(recipient),
                rpc::Quantity256::from_be_bytes(*value.as_be_bytes()),
                rpc::Quantity256::from_be_bytes(*nonce.as_be_bytes()),
                rpc::Quantity256::from_be_bytes(*priority_fee.as_be_bytes()),
                rpc::Quantity256::from_be_bytes(*maximum_fee.as_be_bytes()),
            )
            .map(|value| Word::from_be_bytes(*value.as_be_bytes()))
            .map_err(|_| ())
    }

    fn send_raw_transaction(&self, signed: &[u8]) -> Result<[u8; 32], ()> {
        self.0
            .send_raw_transaction(signed)
            .map(|hash| *hash.as_bytes())
            .map_err(|_| ())
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct Word([u8; 32]);

impl Word {
    const ZERO: Self = Self([0; 32]);

    const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn from_u64(value: u64) -> Self {
        let mut bytes = [0_u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }

    const fn as_be_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    fn checked_add(self, right: Self) -> Option<Self> {
        let mut output = [0_u8; 32];
        let mut carry = 0_u16;
        for index in (0..32).rev() {
            let sum = u16::from(self.0[index]) + u16::from(right.0[index]) + carry;
            output[index] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
        (carry == 0).then_some(Self(output))
    }

    fn checked_mul_u64(self, multiplier: u64) -> Option<Self> {
        let mut result = Self::ZERO;
        let mut addend = self;
        let mut remaining = multiplier;
        while remaining != 0 {
            if remaining & 1 == 1 {
                result = result.checked_add(addend)?;
            }
            remaining >>= 1;
            if remaining != 0 {
                addend = addend.checked_add(addend)?;
            }
        }
        Some(result)
    }

    fn checked_mul_small(self, multiplier: u8) -> Option<Self> {
        let mut output = [0_u8; 32];
        let mut carry = 0_u16;
        for index in (0..32).rev() {
            let product = u16::from(self.0[index]) * u16::from(multiplier) + carry;
            output[index] = (product & 0xff) as u8;
            carry = product >> 8;
        }
        (carry == 0).then_some(Self(output))
    }

    fn checked_add_small(self, value: u8) -> Option<Self> {
        self.checked_add(Self::from_u64(u64::from(value)))
    }

    fn div_mod_small(&mut self, divisor: u8) -> u8 {
        let mut remainder = 0_u16;
        for byte in &mut self.0 {
            let value = (remainder << 8) | u16::from(*byte);
            *byte = (value / u16::from(divisor)) as u8;
            remainder = value % u16::from(divisor);
        }
        remainder as u8
    }
}

#[derive(Clone, Copy)]
enum BackendError {
    StorageUnavailable,
    AlreadyExists,
    NotFound,
    LegacyNotFound,
    InvalidPassword,
    PasswordMismatch,
    VaultAuthentication,
    VaultInvalid,
    InvalidMnemonic,
    InvalidPrivateKey,
    WalletMetadataInvalid,
    WalletChanged,
    GenerationPending,
    NoPendingGeneration,
    GenerationExpired,
    MigrationCleanup,
    MnemonicUnavailable,
    RandomnessUnavailable,
    CryptographicFailure,
    Locked,
    RpcUnavailable,
    BalanceUnavailable,
    InvalidAddress,
    InvalidAmount,
    AmountLimit,
    InvalidFeeInput,
    FeeCombination,
    FeeLimit,
    FasterUnavailable,
    QuoteExpired,
    QuoteChanged,
    AccountChanged,
    UnsupportedTransfer,
    InsufficientBalance,
    BroadcastUnknown,
    HashMismatch,
    PendingExists,
    PendingInvalid,
    PendingCleanup,
    NoPreparedTransfer,
    PreparedInvalid,
}

impl std::fmt::Debug for BackendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::StorageUnavailable => "BackendError::StorageUnavailable",
            Self::AlreadyExists => "BackendError::AlreadyExists",
            Self::NotFound => "BackendError::NotFound",
            Self::LegacyNotFound => "BackendError::LegacyNotFound",
            Self::InvalidPassword => "BackendError::InvalidPassword",
            Self::PasswordMismatch => "BackendError::PasswordMismatch",
            Self::VaultAuthentication => "BackendError::VaultAuthentication",
            Self::VaultInvalid => "BackendError::VaultInvalid",
            Self::InvalidMnemonic => "BackendError::InvalidMnemonic",
            Self::InvalidPrivateKey => "BackendError::InvalidPrivateKey",
            Self::WalletMetadataInvalid => "BackendError::WalletMetadataInvalid",
            Self::WalletChanged => "BackendError::WalletChanged",
            Self::GenerationPending => "BackendError::GenerationPending",
            Self::NoPendingGeneration => "BackendError::NoPendingGeneration",
            Self::GenerationExpired => "BackendError::GenerationExpired",
            Self::MigrationCleanup => "BackendError::MigrationCleanup",
            Self::MnemonicUnavailable => "BackendError::MnemonicUnavailable",
            Self::RandomnessUnavailable => "BackendError::RandomnessUnavailable",
            Self::CryptographicFailure => "BackendError::CryptographicFailure",
            Self::Locked => "BackendError::Locked",
            Self::RpcUnavailable => "BackendError::RpcUnavailable",
            Self::BalanceUnavailable => "BackendError::BalanceUnavailable",
            Self::InvalidAddress => "BackendError::InvalidAddress",
            Self::InvalidAmount => "BackendError::InvalidAmount",
            Self::AmountLimit => "BackendError::AmountLimit",
            Self::InvalidFeeInput => "BackendError::InvalidFeeInput",
            Self::FeeCombination => "BackendError::FeeCombination",
            Self::FeeLimit => "BackendError::FeeLimit",
            Self::FasterUnavailable => "BackendError::FasterUnavailable",
            Self::QuoteExpired => "BackendError::QuoteExpired",
            Self::QuoteChanged => "BackendError::QuoteChanged",
            Self::AccountChanged => "BackendError::AccountChanged",
            Self::UnsupportedTransfer => "BackendError::UnsupportedTransfer",
            Self::InsufficientBalance => "BackendError::InsufficientBalance",
            Self::BroadcastUnknown => "BackendError::BroadcastUnknown",
            Self::HashMismatch => "BackendError::HashMismatch",
            Self::PendingExists => "BackendError::PendingExists",
            Self::PendingInvalid => "BackendError::PendingInvalid",
            Self::PendingCleanup => "BackendError::PendingCleanup",
            Self::NoPreparedTransfer => "BackendError::NoPreparedTransfer",
            Self::PreparedInvalid => "BackendError::PreparedInvalid",
        })
    }
}

fn error_text(error: BackendError) -> String {
    match error {
        BackendError::StorageUnavailable => "지갑 저장소를 준비하지 못했습니다.".to_owned(),
        BackendError::AlreadyExists => "이미 Sepolia 테스트 지갑이 있습니다.".to_owned(),
        BackendError::NotFound => "저장된 Sepolia 테스트 지갑이 없습니다.".to_owned(),
        BackendError::LegacyNotFound => "마이그레이션할 v1 테스트 지갑이 없습니다.".to_owned(),
        BackendError::InvalidPassword => "비밀번호 형식이 올바르지 않습니다.".to_owned(),
        BackendError::PasswordMismatch => "새 비밀번호 확인이 일치하지 않습니다.".to_owned(),
        BackendError::VaultAuthentication => {
            "비밀번호가 틀렸거나 지갑 파일이 손상되었습니다.".to_owned()
        }
        BackendError::VaultInvalid => "지갑 파일 형식이 올바르지 않습니다.".to_owned(),
        BackendError::InvalidMnemonic => {
            "영어 복구 문구와 체크섬을 확인해 주세요.".to_owned()
        }
        BackendError::InvalidPrivateKey => {
            "개인 키는 0x 접두사 선택과 정확한 64자리 16진수여야 합니다.".to_owned()
        }
        BackendError::WalletMetadataInvalid => {
            "지갑 계정 메타데이터 안전 검증에 실패했습니다.".to_owned()
        }
        BackendError::WalletChanged => {
            "열린 지갑과 현재 저장된 지갑이 일치하지 않습니다.".to_owned()
        }
        BackendError::GenerationPending => {
            "먼저 표시된 복구 문구의 백업을 확인하거나 취소해 주세요.".to_owned()
        }
        BackendError::NoPendingGeneration => {
            "확인할 새 복구 문구가 없습니다. 다시 생성해 주세요.".to_owned()
        }
        BackendError::GenerationExpired => {
            "복구 문구 확인 시간이 끝났습니다. 새 지갑 생성을 다시 시작해 주세요.".to_owned()
        }
        BackendError::MigrationCleanup => {
            "v2 지갑은 저장됐지만 이전 v1 파일을 정리하지 못했습니다. 앱을 다시 열어 주세요."
                .to_owned()
        }
        BackendError::MnemonicUnavailable => {
            "이 지갑은 복구 문구로 만든 지갑이 아니어서 복구 문구를 내보낼 수 없습니다. v1 지갑은 먼저 v2로 이전해도 원래 개인 키 지갑으로 유지됩니다."
                .to_owned()
        }
        BackendError::RandomnessUnavailable | BackendError::CryptographicFailure => {
            "안전한 키 처리를 완료하지 못했습니다.".to_owned()
        }
        BackendError::Locked => "먼저 Sepolia 테스트 지갑을 열어 주세요.".to_owned(),
        BackendError::RpcUnavailable => "Sepolia 연결을 확인하지 못했습니다.".to_owned(),
        BackendError::BalanceUnavailable => "Sepolia 잔액을 확인하지 못했습니다.".to_owned(),
        BackendError::InvalidAddress => "받는 주소가 올바르지 않습니다.".to_owned(),
        BackendError::InvalidAmount => "보낼 금액이 올바르지 않습니다.".to_owned(),
        BackendError::AmountLimit => {
            "한 번에 최대 10 Sepolia ETH까지만 보낼 수 있습니다.".to_owned()
        }
        BackendError::InvalidFeeInput => {
            "직접 입력한 Gwei 수수료 형식이 올바르지 않습니다.".to_owned()
        }
        BackendError::FeeCombination => {
            "최대 수수료는 0보다 크고 현재 기본 수수료와 최대 우선 수수료의 합 이상이어야 합니다."
                .to_owned()
        }
        BackendError::FeeLimit => "현재 수수료가 데모 안전 한도를 넘었습니다.".to_owned(),
        BackendError::FasterUnavailable => {
            "현재 추천값에서는 빠른 수수료를 안전 한도 안에서 만들 수 없습니다. 추천 또는 직접 입력을 사용해 주세요."
                .to_owned()
        }
        BackendError::QuoteExpired => {
            "수수료 정보가 만료되었습니다. 전송 내용을 다시 준비해 주세요.".to_owned()
        }
        BackendError::QuoteChanged => {
            "현재 기본 수수료가 준비한 최대 수수료와 맞지 않습니다. 다시 준비해 주세요."
                .to_owned()
        }
        BackendError::AccountChanged => {
            "계정의 전송 순서가 바뀌었습니다. 전송 내용을 다시 준비해 주세요.".to_owned()
        }
        BackendError::UnsupportedTransfer => {
            "이 데모는 가스 한도 21,000인 일반 ETH 전송만 지원합니다.".to_owned()
        }
        BackendError::InsufficientBalance => {
            "수수료를 포함한 Sepolia 잔액이 부족합니다.".to_owned()
        }
        BackendError::BroadcastUnknown => {
            "거래 전송 상태가 불확실합니다. 잠시 후 잔액을 확인해 주세요.".to_owned()
        }
        BackendError::HashMismatch => "Sepolia 노드의 거래 확인값이 일치하지 않습니다.".to_owned(),
        BackendError::PendingExists => {
            "이전 거래의 전송 상태를 먼저 확인하거나 같은 거래를 다시 전송해 주세요.".to_owned()
        }
        BackendError::PendingInvalid => "보류 중인 거래 기록이 손상되었습니다.".to_owned(),
        BackendError::PendingCleanup => {
            "거래는 확인됐지만 보류 기록을 정리하지 못했습니다.".to_owned()
        }
        BackendError::NoPreparedTransfer => "먼저 거래 내용을 미리 확인해 주세요.".to_owned(),
        BackendError::PreparedInvalid => "준비된 거래의 안전 검증에 실패했습니다.".to_owned(),
    }
}

fn take_sensitive_zeroizing(value: SensitiveText) -> Zeroizing<String> {
    value.into_zeroizing()
}

fn take_sensitive(value: SensitiveText) -> String {
    let mut value = value.into_zeroizing();
    std::mem::take(&mut *value)
}

fn matching_vault_password(
    password: SensitiveText,
    confirmation: SensitiveText,
) -> Result<VaultPassword, BackendError> {
    let mut password = take_sensitive_zeroizing(password);
    let confirmation = take_sensitive_zeroizing(confirmation);
    if password.as_bytes() != confirmation.as_bytes() {
        return Err(BackendError::PasswordMismatch);
    }
    VaultPassword::new(std::mem::take(&mut *password)).map_err(map_vault_error)
}

fn confirmed_metadata(origin: VaultOrigin) -> Result<VaultCreationMetadata, BackendError> {
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BackendError::StorageUnavailable)?
        .as_secs();
    VaultCreationMetadata::confirmed(origin, created_at, 1).map_err(map_vault_error)
}

fn validated_wallet_metadata(
    wallet: &WalletSecret,
) -> Result<([u8; 20], WalletKind, u8), BackendError> {
    let account_zero = wallet
        .account(0)
        .ok_or(BackendError::WalletMetadataInvalid)?;
    if account_zero.requested_index() != 0 || account_zero.actual_index() != 0 {
        return Err(BackendError::WalletMetadataInvalid);
    }
    let address = *account_zero.address().as_bytes();
    match wallet.source() {
        WalletSource::Mnemonic => {
            let word_count = wallet
                .word_count()
                .filter(|count| matches!(count, 12 | 15 | 18 | 21 | 24))
                .ok_or(BackendError::WalletMetadataInvalid)?;
            let account_one = wallet
                .account(1)
                .ok_or(BackendError::WalletMetadataInvalid)?;
            if wallet.account_count() != 2
                || wallet.account(2).is_some()
                || account_one.requested_index() != 1
                || account_one.actual_index() != 1
                || account_one.address().as_bytes() == &address
            {
                return Err(BackendError::WalletMetadataInvalid);
            }
            Ok((
                address,
                WalletKind::V2Mnemonic { word_count },
                wallet.account_count(),
            ))
        }
        WalletSource::RawPrivateKey => {
            if wallet.word_count().is_some()
                || wallet.account_count() != 1
                || wallet.account(1).is_some()
            {
                return Err(BackendError::WalletMetadataInvalid);
            }
            Ok((address, WalletKind::V2RawPrivateKey, 1))
        }
    }
}

fn secret_reveal(export: SecretExport) -> Result<SecretReveal, BackendError> {
    let (kind, text) = export.into_zeroizing_text();
    let kind = match kind {
        SecretExportKind::Mnemonic => SecretRevealKind::Mnemonic,
        SecretExportKind::AccountPrivateKey => SecretRevealKind::AccountPrivateKey,
    };
    Ok(SecretReveal::new(kind, text))
}

const fn map_secret_error(error: SecretError) -> BackendError {
    match error {
        SecretError::RandomnessUnavailable => BackendError::RandomnessUnavailable,
        SecretError::InvalidMnemonic => BackendError::InvalidMnemonic,
        SecretError::InvalidPrivateKey => BackendError::InvalidPrivateKey,
        SecretError::UnsupportedAccount | SecretError::DerivationFailed => {
            BackendError::WalletMetadataInvalid
        }
        SecretError::ExportUnavailable => BackendError::MnemonicUnavailable,
        SecretError::CryptographicFailure => BackendError::CryptographicFailure,
    }
}

const fn map_vault_error(error: VaultError) -> BackendError {
    match error {
        VaultError::InvalidPassword => BackendError::InvalidPassword,
        VaultError::InvalidMetadata => BackendError::WalletMetadataInvalid,
        VaultError::RandomnessUnavailable => BackendError::RandomnessUnavailable,
        VaultError::CryptographicFailure => BackendError::CryptographicFailure,
        VaultError::AuthenticationFailed => BackendError::VaultAuthentication,
    }
}

fn validate_password(password: &str) -> Result<(), BackendError> {
    if !(MINIMUM_PASSWORD_BYTES..=MAXIMUM_PASSWORD_BYTES).contains(&password.len())
        || password.chars().any(char::is_control)
    {
        return Err(BackendError::InvalidPassword);
    }
    Ok(())
}

#[cfg(test)]
fn generate_private_key() -> Result<Zeroizing<[u8; KEY_BYTES]>, BackendError> {
    for _ in 0..8 {
        let mut candidate = Zeroizing::new([0_u8; KEY_BYTES]);
        getrandom::fill(candidate.as_mut()).map_err(|_| BackendError::RandomnessUnavailable)?;
        if SecretKey::from_byte_array(*candidate).is_ok() {
            return Ok(candidate);
        }
    }
    Err(BackendError::RandomnessUnavailable)
}

fn address_from_private_key(private_key: &[u8; 32]) -> Result<[u8; 20], BackendError> {
    let secret =
        SecretKey::from_byte_array(*private_key).map_err(|_| BackendError::CryptographicFailure)?;
    let public = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
    Ok(address_from_public_key(&public))
}

fn address_from_public_key(public: &PublicKey) -> [u8; 20] {
    let serialized = public.serialize_uncompressed();
    let digest = Keccak256::digest(&serialized[1..]);
    let mut address = [0_u8; 20];
    address.copy_from_slice(&digest[12..]);
    address
}

#[cfg(test)]
fn seal_vault(
    private_key: &[u8; KEY_BYTES],
    password: &str,
) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    let mut vault_id = [0_u8; 16];
    let mut salt = [0_u8; SALT_BYTES];
    let mut nonce = [0_u8; NONCE_BYTES];
    fill_random_nonzero(&mut vault_id)?;
    fill_random_nonzero(&mut salt)?;
    fill_random_nonzero(&mut nonce)?;
    let header = encode_vault_header(vault_id, salt, nonce);
    let key = derive_vault_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: private_key,
                aad: &header,
            },
        )
        .map_err(|_| BackendError::CryptographicFailure)?;
    if ciphertext.len() != VAULT_CIPHERTEXT_BYTES {
        return Err(BackendError::CryptographicFailure);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(VAULT_FILE_BYTES));
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(&ciphertext);
    Ok(bytes)
}

fn open_vault(bytes: &[u8], password: &str) -> Result<Zeroizing<[u8; KEY_BYTES]>, BackendError> {
    let header = parse_vault_header(bytes)?;
    let key = derive_vault_key(password, &header.salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&header.nonce),
            Payload {
                msg: &bytes[VAULT_HEADER_BYTES..],
                aad: &bytes[..VAULT_HEADER_BYTES],
            },
        )
        .map_err(|_| BackendError::VaultAuthentication)?;
    let mut plaintext = Zeroizing::new(plaintext);
    let key_bytes: [u8; KEY_BYTES] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| BackendError::VaultInvalid)?;
    if SecretKey::from_byte_array(key_bytes).is_err() {
        plaintext.zeroize();
        return Err(BackendError::VaultAuthentication);
    }
    plaintext.zeroize();
    Ok(Zeroizing::new(key_bytes))
}

struct VaultHeader {
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
}

#[cfg(test)]
fn encode_vault_header(
    vault_id: [u8; 16],
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
) -> [u8; VAULT_HEADER_BYTES] {
    let mut header = [0_u8; VAULT_HEADER_BYTES];
    header[0..8].copy_from_slice(VAULT_MAGIC);
    header[8..10].copy_from_slice(&VAULT_VERSION.to_be_bytes());
    header[10..12].copy_from_slice(&VAULT_HEADER_BYTES_U16.to_be_bytes());
    header[12..14].copy_from_slice(&VAULT_PASSWORD_PROFILE.to_be_bytes());
    header[14..16].copy_from_slice(&VAULT_KDF_ARGON2ID.to_be_bytes());
    header[16..18].copy_from_slice(&VAULT_AEAD_XCHACHA20_POLY1305.to_be_bytes());
    header[18..20].copy_from_slice(&VAULT_PAYLOAD_RAW_KEY.to_be_bytes());
    header[20..24].copy_from_slice(&ARGON2_MEMORY_KIB.to_be_bytes());
    header[24..28].copy_from_slice(&ARGON2_ITERATIONS.to_be_bytes());
    header[28..32].copy_from_slice(&ARGON2_PARALLELISM.to_be_bytes());
    header[32..48].copy_from_slice(&vault_id);
    header[48..64].copy_from_slice(&salt);
    header[64..88].copy_from_slice(&nonce);
    header[88..92].copy_from_slice(&(VAULT_CIPHERTEXT_BYTES as u32).to_be_bytes());
    header[92..96].copy_from_slice(&(rpc::SEPOLIA_CHAIN_ID as u32).to_be_bytes());
    header
}

fn parse_vault_header(bytes: &[u8]) -> Result<VaultHeader, BackendError> {
    if bytes.len() != VAULT_FILE_BYTES
        || bytes.get(0..8) != Some(VAULT_MAGIC.as_slice())
        || read_u16(bytes, 8)? != VAULT_VERSION
        || read_u16(bytes, 10)? != VAULT_HEADER_BYTES_U16
        || read_u16(bytes, 12)? != VAULT_PASSWORD_PROFILE
        || read_u16(bytes, 14)? != VAULT_KDF_ARGON2ID
        || read_u16(bytes, 16)? != VAULT_AEAD_XCHACHA20_POLY1305
        || read_u16(bytes, 18)? != VAULT_PAYLOAD_RAW_KEY
        || read_u32(bytes, 20)? != ARGON2_MEMORY_KIB
        || read_u32(bytes, 24)? != ARGON2_ITERATIONS
        || read_u32(bytes, 28)? != ARGON2_PARALLELISM
        || read_u32(bytes, 88)? != VAULT_CIPHERTEXT_BYTES as u32
        || read_u32(bytes, 92)? != rpc::SEPOLIA_CHAIN_ID as u32
    {
        return Err(BackendError::VaultInvalid);
    }
    let vault_id = array_at::<16>(bytes, 32)?;
    let salt = array_at::<SALT_BYTES>(bytes, 48)?;
    let nonce = array_at::<NONCE_BYTES>(bytes, 64)?;
    if vault_id == [0; 16] || salt == [0; SALT_BYTES] || nonce == [0; NONCE_BYTES] {
        return Err(BackendError::VaultInvalid);
    }
    Ok(VaultHeader { salt, nonce })
}

fn derive_vault_key(
    password: &str,
    salt: &[u8; SALT_BYTES],
) -> Result<Zeroizing<[u8; 32]>, BackendError> {
    validate_password(password)?;
    let password = Zeroizing::new(password.as_bytes().to_vec());
    let parameters = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(|_| BackendError::CryptographicFailure)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters);
    let mut master = Zeroizing::new([0_u8; 32]);
    argon2
        .hash_password_into(password.as_slice(), salt, master.as_mut())
        .map_err(|_| BackendError::CryptographicFailure)?;
    let hkdf = Hkdf::<Sha256>::new(None, master.as_ref());
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(HKDF_DOMAIN, output.as_mut())
        .map_err(|_| BackendError::CryptographicFailure)?;
    Ok(output)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, BackendError> {
    Ok(u16::from_be_bytes(array_at(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, BackendError> {
    Ok(u32::from_be_bytes(array_at(bytes, offset)?))
}

fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], BackendError> {
    let end = offset.checked_add(N).ok_or(BackendError::VaultInvalid)?;
    bytes
        .get(offset..end)
        .ok_or(BackendError::VaultInvalid)?
        .try_into()
        .map_err(|_| BackendError::VaultInvalid)
}

#[cfg(test)]
fn fill_random_nonzero(bytes: &mut [u8]) -> Result<(), BackendError> {
    for _ in 0..4 {
        getrandom::fill(bytes).map_err(|_| BackendError::RandomnessUnavailable)?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(());
        }
    }
    Err(BackendError::RandomnessUnavailable)
}

fn path_may_exist(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        // A metadata/permission error is not evidence that the security-
        // relevant name is absent. Callers therefore quarantine or reject.
        Err(_) => true,
    }
}

fn read_vault(path: &Path) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    let file = File::open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            BackendError::NotFound
        } else {
            BackendError::StorageUnavailable
        }
    })?;
    let length = file
        .metadata()
        .map_err(|_| BackendError::StorageUnavailable)?
        .len();
    if length != VAULT_FILE_BYTES as u64 {
        return Err(BackendError::VaultInvalid);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(VAULT_FILE_BYTES));
    file.take((VAULT_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| BackendError::StorageUnavailable)?;
    if bytes.len() != VAULT_FILE_BYTES {
        return Err(BackendError::VaultInvalid);
    }
    Ok(bytes)
}

fn read_v2_vault(path: &Path) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    let file = File::open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            BackendError::NotFound
        } else {
            BackendError::StorageUnavailable
        }
    })?;
    let length = file
        .metadata()
        .map_err(|_| BackendError::StorageUnavailable)?
        .len();
    if length == 0 || length > MAX_V2_VAULT_BYTES as u64 {
        return Err(BackendError::VaultInvalid);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(length as usize));
    file.take((MAX_V2_VAULT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| BackendError::StorageUnavailable)?;
    if bytes.len() as u64 != length || bytes.len() > MAX_V2_VAULT_BYTES {
        return Err(BackendError::VaultInvalid);
    }
    Ok(bytes)
}

fn remove_legacy_vault(path: &Path) -> Result<(), BackendError> {
    let parent = path.parent().ok_or(BackendError::StorageUnavailable)?;
    let parent_directory = DurableParentDirectory::open(parent)?;
    fs::remove_file(path).map_err(|_| BackendError::StorageUnavailable)?;
    parent_directory.flush()
}

#[cfg(test)]
fn write_new_vault(path: &Path, bytes: &[u8]) -> Result<(), BackendError> {
    if bytes.len() != VAULT_FILE_BYTES {
        return Err(BackendError::VaultInvalid);
    }
    write_new_file(path, bytes)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), BackendError> {
    let parent = path.parent().ok_or(BackendError::StorageUnavailable)?;
    fs::create_dir_all(parent).map_err(|_| BackendError::StorageUnavailable)?;
    // Hold the exact parent open without delete sharing before changing it.
    // This also proves up front that the final component is not a reparse point.
    let parent_directory = DurableParentDirectory::open(parent)?;
    // Claim the final name atomically. A pre-check plus rename lets two
    // processes both prepare data and then replace each other on platforms
    // where rename-over-existing is allowed.
    let mut file = match OpenOptions::new().create_new(true).write(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(BackendError::AlreadyExists);
        }
        Err(_) => return Err(BackendError::StorageUnavailable),
    };
    let result = (|| {
        file.write_all(bytes)
            .map_err(|_| BackendError::StorageUnavailable)?;
        file.sync_all()
            .map_err(|_| BackendError::StorageUnavailable)?;
        Ok(())
    })();
    drop(file);
    if result.is_err() {
        // We created this exact path with create_new, so a failed write can
        // only remove our own partial record. A process crash intentionally
        // leaves a partial file behind, which makes subsequent opens fail
        // closed instead of silently reusing the name.
        if fs::remove_file(path).is_ok() {
            let _ = parent_directory.flush();
        }
        return result;
    }
    // The file's bytes alone are not enough: the directory entry must also be
    // durable before callers may treat a vault or signed pending record as
    // committed. A failure leaves the complete record in place and fails
    // closed, so a retry cannot accidentally sign a second transaction.
    parent_directory.flush()
}

struct DurableParentDirectory {
    directory: File,
}

#[cfg(windows)]
impl DurableParentDirectory {
    fn open(path: &Path) -> Result<Self, BackendError> {
        use std::os::windows::ffi::OsStrExt;

        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err(BackendError::StorageUnavailable);
        }
        wide.push(0);

        // SAFETY: `wide` is NUL terminated and remains live for the call. The
        // missing delete share pins the exact directory while it is modified.
        // OPEN_REPARSE_POINT opens the final component itself for verification.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                FILE_READ_ATTRIBUTES.0 | FILE_LIST_DIRECTORY.0 | GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .map_err(|_| BackendError::StorageUnavailable)?;
        // SAFETY: CreateFileW returned one owned handle, transferred to File
        // exactly once so every later error path closes it through RAII.
        let directory = unsafe { File::from_raw_handle(handle.0 as RawHandle) };
        let attributes = directory
            .metadata()
            .map_err(|_| BackendError::StorageUnavailable)?
            .file_attributes();
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            return Err(BackendError::StorageUnavailable);
        }
        Ok(Self { directory })
    }

    fn flush(&self) -> Result<(), BackendError> {
        // Windows documents FlushFileBuffers primarily for file/volume
        // handles. NTFS accepts a directory handle opened with backup
        // semantics; another filesystem must prove the same operation or this
        // demo fails closed instead of claiming durable pending state.
        // SAFETY: this is the live, write-capable directory handle we own.
        unsafe { FlushFileBuffers(HANDLE(self.directory.as_raw_handle())) }
            .map_err(|_| BackendError::StorageUnavailable)
    }
}

#[cfg(not(windows))]
impl DurableParentDirectory {
    fn open(path: &Path) -> Result<Self, BackendError> {
        let directory = File::open(path).map_err(|_| BackendError::StorageUnavailable)?;
        if !directory
            .metadata()
            .map_err(|_| BackendError::StorageUnavailable)?
            .is_dir()
        {
            return Err(BackendError::StorageUnavailable);
        }
        Ok(Self { directory })
    }

    fn flush(&self) -> Result<(), BackendError> {
        self.directory
            .sync_all()
            .map_err(|_| BackendError::StorageUnavailable)
    }
}

struct PendingRecord {
    transaction_hash: [u8; 32],
    raw_transaction: Zeroizing<Vec<u8>>,
}

fn write_new_pending(
    path: &Path,
    transaction_hash: [u8; 32],
    raw_transaction: &[u8],
) -> Result<(), BackendError> {
    if !(2..=MAX_PENDING_RAW_BYTES).contains(&raw_transaction.len())
        || raw_transaction.first() != Some(&2)
        || keccak32(raw_transaction) != transaction_hash
    {
        return Err(BackendError::PendingInvalid);
    }
    let raw_length =
        u32::try_from(raw_transaction.len()).map_err(|_| BackendError::PendingInvalid)?;
    let mut record = Zeroizing::new(Vec::with_capacity(
        PENDING_HEADER_BYTES + raw_transaction.len(),
    ));
    record.extend_from_slice(PENDING_MAGIC);
    record.extend_from_slice(&PENDING_VERSION.to_be_bytes());
    record.extend_from_slice(&PENDING_HEADER_BYTES_U16.to_be_bytes());
    record.extend_from_slice(&(rpc::SEPOLIA_CHAIN_ID as u32).to_be_bytes());
    record.extend_from_slice(&transaction_hash);
    record.extend_from_slice(&raw_length.to_be_bytes());
    record.extend_from_slice(&[0_u8; 4]);
    record.extend_from_slice(raw_transaction);
    write_new_file(path, record.as_slice()).map_err(|error| match error {
        BackendError::AlreadyExists => BackendError::PendingExists,
        other => other,
    })
}

fn read_pending(path: &Path) -> Result<PendingRecord, BackendError> {
    let file = File::open(path).map_err(|_| BackendError::PendingInvalid)?;
    let length = usize::try_from(
        file.metadata()
            .map_err(|_| BackendError::PendingInvalid)?
            .len(),
    )
    .map_err(|_| BackendError::PendingInvalid)?;
    if !(PENDING_HEADER_BYTES + 2..=PENDING_HEADER_BYTES + MAX_PENDING_RAW_BYTES).contains(&length)
    {
        return Err(BackendError::PendingInvalid);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(length));
    file.take((PENDING_HEADER_BYTES + MAX_PENDING_RAW_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| BackendError::PendingInvalid)?;
    if bytes.len() != length
        || bytes.get(0..8) != Some(PENDING_MAGIC.as_slice())
        || read_u16(&bytes, 8).map_err(|_| BackendError::PendingInvalid)? != PENDING_VERSION
        || read_u16(&bytes, 10).map_err(|_| BackendError::PendingInvalid)?
            != PENDING_HEADER_BYTES_U16
        || read_u32(&bytes, 12).map_err(|_| BackendError::PendingInvalid)?
            != rpc::SEPOLIA_CHAIN_ID as u32
        || bytes.get(52..56) != Some(&[0_u8; 4][..])
    {
        return Err(BackendError::PendingInvalid);
    }
    let raw_length =
        usize::try_from(read_u32(&bytes, 48).map_err(|_| BackendError::PendingInvalid)?)
            .map_err(|_| BackendError::PendingInvalid)?;
    if !(2..=MAX_PENDING_RAW_BYTES).contains(&raw_length)
        || length != PENDING_HEADER_BYTES + raw_length
    {
        return Err(BackendError::PendingInvalid);
    }
    let transaction_hash = array_at::<32>(&bytes, 16).map_err(|_| BackendError::PendingInvalid)?;
    let raw_transaction = Zeroizing::new(bytes[PENDING_HEADER_BYTES..].to_vec());
    if raw_transaction.first() != Some(&2)
        || keccak32(raw_transaction.as_slice()) != transaction_hash
    {
        return Err(BackendError::PendingInvalid);
    }
    Ok(PendingRecord {
        transaction_hash,
        raw_transaction,
    })
}

fn remove_pending(path: &Path) -> Result<(), BackendError> {
    let parent = path.parent().ok_or(BackendError::PendingCleanup)?;
    // Acquire and validate the exact directory before deleting the only durable
    // copy. Keeping this handle open prevents replacement between deletion and
    // the durability barrier.
    let parent_directory =
        DurableParentDirectory::open(parent).map_err(|_| BackendError::PendingCleanup)?;
    fs::remove_file(path).map_err(|_| BackendError::PendingCleanup)?;
    parent_directory
        .flush()
        .map_err(|_| BackendError::PendingCleanup)
}

fn sibling_pending_path(vault_path: &Path) -> Result<PathBuf, String> {
    if vault_path.file_name().is_none() {
        return Err(error_text(BackendError::StorageUnavailable));
    }
    Ok(vault_path.with_file_name("pending-v1.bin"))
}

fn resolve_fee_plan(
    selection: FeeSelection,
    quote: NetworkFeeQuote,
) -> Result<FrozenFeePlan, BackendError> {
    validate_fee_values(
        quote.base_fee,
        quote.recommended_priority_fee,
        quote.recommended_maximum_fee,
    )?;
    let (mode_label, priority_fee, maximum_fee) = match selection {
        FeeSelection::Recommended => (
            "추천",
            quote.recommended_priority_fee,
            quote.recommended_maximum_fee,
        ),
        FeeSelection::Faster => {
            let doubled = quote
                .recommended_priority_fee
                .checked_mul_u64(2)
                .ok_or(BackendError::FasterUnavailable)?;
            let priority = std::cmp::min(doubled, Word::from_u64(MAX_PRIORITY_FEE_PER_GAS));
            if priority <= quote.recommended_priority_fee {
                return Err(BackendError::FasterUnavailable);
            }
            let maximum = quote
                .base_fee
                .checked_mul_u64(2)
                .and_then(|base| base.checked_add(priority))
                .ok_or(BackendError::FasterUnavailable)?;
            if validate_fee_values(quote.base_fee, priority, maximum).is_err() {
                return Err(BackendError::FasterUnavailable);
            }
            ("빠르게", priority, maximum)
        }
        FeeSelection::Custom {
            max_priority_fee_per_gas_gwei,
            max_fee_per_gas_gwei,
        } => {
            let priority = parse_gwei(&max_priority_fee_per_gas_gwei)?;
            let maximum = parse_gwei(&max_fee_per_gas_gwei)?;
            validate_fee_values(quote.base_fee, priority, maximum)?;
            ("직접 입력", priority, maximum)
        }
    };
    validate_fee_values(quote.base_fee, priority_fee, maximum_fee)?;
    Ok(FrozenFeePlan {
        mode_label,
        quoted_base_fee: quote.base_fee,
        priority_fee,
        maximum_fee,
    })
}

fn ensure_quote_live(clock: &dyn MonotonicClock, expires_at: Instant) -> Result<(), BackendError> {
    if clock.now() < expires_at {
        Ok(())
    } else {
        Err(BackendError::QuoteExpired)
    }
}

fn conservative_remaining_quote_seconds(
    clock: &dyn MonotonicClock,
    expires_at: Instant,
) -> Result<u64, BackendError> {
    let whole_seconds = expires_at.saturating_duration_since(clock.now()).as_secs();
    if whole_seconds < MIN_CONFIRMABLE_QUOTE_SECONDS {
        Err(BackendError::QuoteExpired)
    } else {
        Ok(whole_seconds)
    }
}

fn parse_gwei(value: &str) -> Result<Word, BackendError> {
    if value.is_empty()
        || value.len() > MAX_GWEI_INPUT_BYTES
        || value.trim() != value
        || value
            .bytes()
            .any(|byte| matches!(byte, b'+' | b'-' | b'e' | b'E'))
    {
        return Err(BackendError::InvalidFeeInput);
    }
    let mut split = value.split('.');
    let integer = split.next().ok_or(BackendError::InvalidFeeInput)?;
    let fraction = split.next();
    if split.next().is_some()
        || integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(BackendError::InvalidFeeInput);
    }
    let fraction = fraction.unwrap_or("");
    if fraction.len() > 9
        || fraction.bytes().any(|byte| !byte.is_ascii_digit())
        || value.ends_with('.')
    {
        return Err(BackendError::InvalidFeeInput);
    }

    let mut output = Word::ZERO;
    for digit in integer.bytes().chain(fraction.bytes()) {
        output = output
            .checked_mul_small(10)
            .and_then(|word| word.checked_add_small(digit - b'0'))
            .ok_or(BackendError::InvalidFeeInput)?;
    }
    for _ in fraction.len()..9 {
        output = output
            .checked_mul_small(10)
            .ok_or(BackendError::InvalidFeeInput)?;
    }
    Ok(output)
}

fn parse_ether(value: &str) -> Result<Word, BackendError> {
    if value.is_empty()
        || value.trim() != value
        || value
            .bytes()
            .any(|byte| matches!(byte, b'+' | b'-' | b'e' | b'E'))
    {
        return Err(BackendError::InvalidAmount);
    }
    let mut split = value.split('.');
    let integer = split.next().ok_or(BackendError::InvalidAmount)?;
    let fraction = split.next();
    if split.next().is_some()
        || integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
        || (integer.len() > 1 && integer.starts_with('0'))
    {
        return Err(BackendError::InvalidAmount);
    }
    let fraction = fraction.unwrap_or("");
    if fraction.len() > 18
        || fraction.bytes().any(|byte| !byte.is_ascii_digit())
        || value.ends_with('.')
    {
        return Err(BackendError::InvalidAmount);
    }

    let mut output = Word::ZERO;
    for digit in integer.bytes().chain(fraction.bytes()) {
        output = output
            .checked_mul_small(10)
            .and_then(|word| word.checked_add_small(digit - b'0'))
            .ok_or(BackendError::InvalidAmount)?;
    }
    for _ in fraction.len()..18 {
        output = output
            .checked_mul_small(10)
            .ok_or(BackendError::InvalidAmount)?;
    }
    Ok(output)
}

fn format_ether(value: Word) -> String {
    format_decimal_units(value, 18)
}

fn format_gwei(value: Word) -> String {
    format_decimal_units(value, 9)
}

fn format_decimal_units(value: Word, decimals: usize) -> String {
    let mut decimal = decimal_string(value);
    if decimal.len() <= decimals {
        decimal.insert_str(0, &"0".repeat(decimals + 1 - decimal.len()));
    }
    let split = decimal.len() - decimals;
    let mut fraction = decimal.split_off(split);
    while fraction.ends_with('0') {
        fraction.pop();
    }
    if fraction.is_empty() {
        decimal
    } else {
        format!("{decimal}.{fraction}")
    }
}

fn decimal_string(mut value: Word) -> String {
    if value.is_zero() {
        return "0".to_owned();
    }
    let mut reverse = Vec::new();
    while !value.is_zero() {
        reverse.push(b'0' + value.div_mod_small(10));
    }
    reverse.reverse();
    String::from_utf8(reverse).unwrap_or_else(|_| "0".to_owned())
}

fn validate_fee_quote(priority_fee: Word, maximum_fee: Word) -> Result<(), BackendError> {
    if maximum_fee.is_zero() || maximum_fee < priority_fee {
        return Err(BackendError::FeeCombination);
    }
    if priority_fee > Word::from_u64(MAX_PRIORITY_FEE_PER_GAS)
        || maximum_fee > Word::from_u64(MAX_FEE_PER_GAS)
    {
        return Err(BackendError::FeeLimit);
    }
    Ok(())
}

fn validate_fee_values(
    base_fee: Word,
    priority_fee: Word,
    maximum_fee: Word,
) -> Result<(), BackendError> {
    validate_fee_quote(priority_fee, maximum_fee)?;
    let estimated_price = base_fee
        .checked_add(priority_fee)
        .ok_or(BackendError::FeeLimit)?;
    if maximum_fee < estimated_price {
        return Err(BackendError::FeeCombination);
    }
    Ok(())
}

fn parse_address(value: &str) -> Result<[u8; 20], BackendError> {
    let digits = value
        .strip_prefix("0x")
        .filter(|digits| digits.len() == 40)
        .ok_or(BackendError::InvalidAddress)?;
    let mut address = [0_u8; 20];
    for (index, output) in address.iter_mut().enumerate() {
        let high = decode_nibble(digits.as_bytes()[index * 2])?;
        let low = decode_nibble(digits.as_bytes()[index * 2 + 1])?;
        *output = (high << 4) | low;
    }
    if address == [0; 20] {
        return Err(BackendError::InvalidAddress);
    }

    let has_lower = digits.bytes().any(|byte| byte.is_ascii_lowercase());
    let has_upper = digits.bytes().any(|byte| byte.is_ascii_uppercase());
    if has_lower && has_upper && checksum_address(address).get(2..) != Some(digits) {
        return Err(BackendError::InvalidAddress);
    }
    Ok(address)
}

fn decode_nibble(byte: u8) -> Result<u8, BackendError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(BackendError::InvalidAddress),
    }
}

fn checksum_address(address: [u8; 20]) -> String {
    let lowercase = hex_without_prefix(&address);
    let digest = Keccak256::digest(lowercase.as_bytes());
    let mut output = String::with_capacity(42);
    output.push_str("0x");
    for (index, byte) in lowercase.bytes().enumerate() {
        if byte.is_ascii_alphabetic() && hash_nibble(&digest, index) >= 8 {
            output.push(char::from(byte.to_ascii_uppercase()));
        } else {
            output.push(char::from(byte));
        }
    }
    output
}

fn hash_nibble(hash: &[u8], index: usize) -> u8 {
    if index.is_multiple_of(2) {
        hash[index / 2] >> 4
    } else {
        hash[index / 2] & 0x0f
    }
}

struct SignedTransaction {
    bytes: Zeroizing<Vec<u8>>,
    transaction_hash: [u8; 32],
}

#[allow(clippy::too_many_arguments)]
fn sign_native_type_two(
    private_key: &[u8; 32],
    expected_sender: [u8; 20],
    recipient: [u8; 20],
    value: Word,
    nonce: Word,
    gas_limit: Word,
    priority_fee: Word,
    maximum_fee: Word,
) -> Result<SignedTransaction, BackendError> {
    validate_fee_quote(priority_fee, maximum_fee)?;
    if gas_limit != Word::from_u64(NATIVE_TRANSFER_GAS) {
        return Err(BackendError::PreparedInvalid);
    }
    let chain_id = Word::from_u64(rpc::SEPOLIA_CHAIN_ID);
    let unsigned_payload = rlp_list(&[
        rlp_word(chain_id),
        rlp_word(nonce),
        rlp_word(priority_fee),
        rlp_word(maximum_fee),
        rlp_word(gas_limit),
        rlp_bytes(&recipient),
        rlp_word(value),
        rlp_bytes(&[]),
        rlp_list(&[]),
    ]);
    let mut unsigned = Zeroizing::new(Vec::with_capacity(unsigned_payload.len() + 1));
    unsigned.push(2);
    unsigned.extend_from_slice(&unsigned_payload);
    let mut prehash = keccak32(unsigned.as_slice());
    let secret =
        SecretKey::from_byte_array(*private_key).map_err(|_| BackendError::CryptographicFailure)?;
    let signature = Secp256k1::new().sign_ecdsa_recoverable(Message::from_digest(prehash), &secret);
    let (recovery_id, mut compact) = signature.serialize_compact();
    let y_parity =
        u8::try_from(i32::from(recovery_id)).map_err(|_| BackendError::CryptographicFailure)?;
    if y_parity > 1 {
        prehash.zeroize();
        compact.zeroize();
        return Err(BackendError::CryptographicFailure);
    }

    let signed_payload = rlp_list(&[
        rlp_word(chain_id),
        rlp_word(nonce),
        rlp_word(priority_fee),
        rlp_word(maximum_fee),
        rlp_word(gas_limit),
        rlp_bytes(&recipient),
        rlp_word(value),
        rlp_bytes(&[]),
        rlp_list(&[]),
        rlp_integer(&[y_parity]),
        rlp_integer(&compact[..32]),
        rlp_integer(&compact[32..]),
    ]);
    let mut bytes = Zeroizing::new(Vec::with_capacity(signed_payload.len() + 1));
    bytes.push(2);
    bytes.extend_from_slice(&signed_payload);

    let recoverable = RecoverableSignature::from_compact(
        &compact,
        RecoveryId::try_from(i32::from(y_parity))
            .map_err(|_| BackendError::CryptographicFailure)?,
    )
    .map_err(|_| BackendError::CryptographicFailure)?;
    let recovered = Secp256k1::new()
        .recover_ecdsa(Message::from_digest(prehash), &recoverable)
        .map_err(|_| BackendError::CryptographicFailure)?;
    prehash.zeroize();
    compact.zeroize();
    if address_from_public_key(&recovered) != expected_sender {
        return Err(BackendError::CryptographicFailure);
    }
    let transaction_hash = keccak32(bytes.as_slice());
    Ok(SignedTransaction {
        bytes,
        transaction_hash,
    })
}

fn rlp_word(value: Word) -> Vec<u8> {
    rlp_integer(value.as_be_bytes())
}

fn rlp_integer(bytes: &[u8]) -> Vec<u8> {
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    rlp_bytes(&bytes[first..])
}

fn rlp_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return vec![bytes[0]];
    }
    let mut output = Vec::new();
    encode_rlp_length(0x80, 0xb7, bytes.len(), &mut output);
    output.extend_from_slice(bytes);
    output
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_length = items
        .iter()
        .fold(0_usize, |sum, item| sum.saturating_add(item.len()));
    let mut output = Vec::new();
    encode_rlp_length(0xc0, 0xf7, payload_length, &mut output);
    for item in items {
        output.extend_from_slice(item);
    }
    output
}

fn encode_rlp_length(short: u8, long: u8, length: usize, output: &mut Vec<u8>) {
    if length <= 55 {
        output.push(short + length as u8);
        return;
    }
    let encoded = length.to_be_bytes();
    let first = encoded
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(encoded.len() - 1);
    let significant = &encoded[first..];
    output.push(long + significant.len() as u8);
    output.extend_from_slice(significant);
}

fn keccak32(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

fn fixed_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex_without_prefix(bytes))
}

fn hex_without_prefix(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    const TEST_PASSWORD: &str = "correct demo password";

    struct TestRpc {
        balance: Word,
        nonce: Word,
        base_fee: Word,
        priority: Word,
        maximum: Word,
        estimated_gas: Word,
        returned_hash: Option<[u8; 32]>,
        send_fails: bool,
    }

    impl RpcAccess for TestRpc {
        fn verify_sepolia(&self) -> Result<(), ()> {
            Ok(())
        }

        fn balance(&self, _address: [u8; 20]) -> Result<Word, ()> {
            Ok(self.balance)
        }

        fn pending_balance(&self, _address: [u8; 20]) -> Result<Word, ()> {
            Ok(self.balance)
        }

        fn pending_nonce(&self, _address: [u8; 20]) -> Result<Word, ()> {
            Ok(self.nonce)
        }

        fn fee_quote(&self) -> Result<NetworkFeeQuote, ()> {
            Ok(NetworkFeeQuote {
                base_fee: self.base_fee,
                recommended_priority_fee: self.priority,
                recommended_maximum_fee: self.maximum,
            })
        }

        fn latest_base_fee(&self) -> Result<Word, ()> {
            Ok(self.base_fee)
        }

        fn estimate_native_transfer_gas(
            &self,
            _sender: [u8; 20],
            _recipient: [u8; 20],
            _value: Word,
            _nonce: Word,
            _priority_fee: Word,
            _maximum_fee: Word,
        ) -> Result<Word, ()> {
            Ok(self.estimated_gas)
        }

        fn send_raw_transaction(&self, signed: &[u8]) -> Result<[u8; 32], ()> {
            if self.send_fails {
                Err(())
            } else {
                Ok(self.returned_hash.unwrap_or_else(|| keccak32(signed)))
            }
        }
    }

    fn test_rpc() -> TestRpc {
        TestRpc {
            balance: Word::from_u64(2_000_000_000_000_000_000),
            nonce: Word::from_u64(7),
            base_fee: Word::from_u64(500_000_000),
            priority: Word::from_u64(1_000_000_000),
            maximum: Word::from_u64(2_000_000_000),
            estimated_gas: Word::from_u64(NATIVE_TRANSFER_GAS),
            returned_hash: None,
            send_fails: false,
        }
    }

    #[derive(Clone)]
    struct TestClock {
        now: Arc<Mutex<Instant>>,
    }

    impl TestClock {
        fn new(now: Instant) -> Self {
            Self {
                now: Arc::new(Mutex::new(now)),
            }
        }

        fn advance(&self, duration: Duration) {
            let mut now = self.now.lock().expect("test clock lock");
            *now = now.checked_add(duration).expect("test clock range");
        }
    }

    impl MonotonicClock for TestClock {
        fn now(&self) -> Instant {
            *self.now.lock().expect("test clock lock")
        }
    }

    #[derive(Clone)]
    struct MutableRpc {
        state: Arc<Mutex<MutableRpcState>>,
    }

    struct MutableRpcState {
        verify_ok: bool,
        balance: Word,
        nonce: Word,
        base_fee: Word,
        priority: Word,
        maximum: Word,
        estimated_gas: Word,
        verify_calls: usize,
        nonce_calls: usize,
        quote_calls: usize,
        base_fee_calls: usize,
        balance_calls: usize,
        estimate_calls: usize,
        sent: Vec<Vec<u8>>,
        send_fails: bool,
        pending_path_to_require: Option<PathBuf>,
        send_observed_pending: bool,
        expire_clock_on_estimate_call: Option<(TestClock, usize, Duration)>,
    }

    impl MutableRpc {
        fn new() -> Self {
            Self {
                state: Arc::new(Mutex::new(MutableRpcState {
                    verify_ok: true,
                    balance: Word::from_u64(2_000_000_000_000_000_000),
                    nonce: Word::from_u64(7),
                    base_fee: Word::from_u64(500_000_000),
                    priority: Word::from_u64(1_000_000_000),
                    maximum: Word::from_u64(2_000_000_000),
                    estimated_gas: Word::from_u64(NATIVE_TRANSFER_GAS),
                    verify_calls: 0,
                    nonce_calls: 0,
                    quote_calls: 0,
                    base_fee_calls: 0,
                    balance_calls: 0,
                    estimate_calls: 0,
                    sent: Vec::new(),
                    send_fails: false,
                    pending_path_to_require: None,
                    send_observed_pending: false,
                    expire_clock_on_estimate_call: None,
                })),
            }
        }

        fn update(&self, update: impl FnOnce(&mut MutableRpcState)) {
            update(&mut self.state.lock().expect("mutable RPC lock"));
        }
    }

    impl RpcAccess for MutableRpc {
        fn verify_sepolia(&self) -> Result<(), ()> {
            let mut state = self.state.lock().map_err(|_| ())?;
            state.verify_calls += 1;
            state.verify_ok.then_some(()).ok_or(())
        }

        fn balance(&self, _address: [u8; 20]) -> Result<Word, ()> {
            Ok(self.state.lock().map_err(|_| ())?.balance)
        }

        fn pending_balance(&self, _address: [u8; 20]) -> Result<Word, ()> {
            let mut state = self.state.lock().map_err(|_| ())?;
            state.balance_calls += 1;
            Ok(state.balance)
        }

        fn pending_nonce(&self, _address: [u8; 20]) -> Result<Word, ()> {
            let mut state = self.state.lock().map_err(|_| ())?;
            state.nonce_calls += 1;
            Ok(state.nonce)
        }

        fn fee_quote(&self) -> Result<NetworkFeeQuote, ()> {
            let mut state = self.state.lock().map_err(|_| ())?;
            state.quote_calls += 1;
            Ok(NetworkFeeQuote {
                base_fee: state.base_fee,
                recommended_priority_fee: state.priority,
                recommended_maximum_fee: state.maximum,
            })
        }

        fn latest_base_fee(&self) -> Result<Word, ()> {
            let mut state = self.state.lock().map_err(|_| ())?;
            state.base_fee_calls += 1;
            Ok(state.base_fee)
        }

        fn estimate_native_transfer_gas(
            &self,
            _sender: [u8; 20],
            _recipient: [u8; 20],
            _value: Word,
            _nonce: Word,
            _priority_fee: Word,
            _maximum_fee: Word,
        ) -> Result<Word, ()> {
            let (gas, expiration) = {
                let mut state = self.state.lock().map_err(|_| ())?;
                state.estimate_calls += 1;
                let expiration = state
                    .expire_clock_on_estimate_call
                    .as_ref()
                    .filter(|(_, call, _)| *call == state.estimate_calls)
                    .cloned();
                (state.estimated_gas, expiration)
            };
            if let Some((clock, _, duration)) = expiration {
                clock.advance(duration);
            }
            Ok(gas)
        }

        fn send_raw_transaction(&self, signed: &[u8]) -> Result<[u8; 32], ()> {
            let mut state = self.state.lock().map_err(|_| ())?;
            state.sent.push(signed.to_vec());
            if let Some(path) = &state.pending_path_to_require {
                state.send_observed_pending = path.is_file();
            }
            if state.send_fails {
                Err(())
            } else {
                Ok(keccak32(signed))
            }
        }
    }

    fn unlocked_backend(rpc: MutableRpc, clock: TestClock) -> DemoBackend {
        let vault = temporary_vault();
        if let Some(parent) = vault.parent() {
            fs::create_dir_all(parent).expect("create test backend directory");
        }
        let private_key = Zeroizing::new([7_u8; KEY_BYTES]);
        let address = address_from_private_key(&private_key).expect("derive test address");
        let mut backend = DemoBackend::with_rpc_and_clock(vault, rpc, clock);
        backend.unlocked = Some(UnlockedWallet::LegacyV1 {
            private_key,
            address,
        });
        backend.last_balance = Some(Word::ZERO);
        backend
    }

    fn remove_test_backend_files(backend: &DemoBackend) {
        let _ = fs::remove_file(&backend.pending_path);
        let _ = fs::remove_file(&backend.vault_path);
        let _ = fs::remove_file(&backend.vault_v2_path);
        if let Some(parent) = backend.vault_path.parent() {
            let _ = fs::remove_dir(parent);
        }
    }

    fn prepared_mutable_backend() -> (DemoBackend, MutableRpc, TestClock) {
        let rpc = MutableRpc::new();
        let clock = TestClock::new(Instant::now());
        let mut backend = unlocked_backend(rpc.clone(), clock.clone());
        backend
            .prepare_transfer_inner(
                "0x1111111111111111111111111111111111111111",
                "0.25",
                FeeSelection::Recommended,
            )
            .expect("prepare mutable backend transfer");
        (backend, rpc, clock)
    }

    fn temporary_vault() -> PathBuf {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).unwrap_or_else(|_| random.copy_from_slice(&[7; 8]));
        std::env::temp_dir()
            .join(format!(
                "your-wallet-sepolia-test-{}",
                hex_without_prefix(&random)
            ))
            .join("vault-v1.bin")
    }

    fn sensitive(value: &str) -> SensitiveText {
        SensitiveText::new(value.to_owned())
    }

    fn v2_backend(clock: TestClock) -> DemoBackend {
        DemoBackend::with_rpc_and_clock(temporary_vault(), test_rpc(), clock)
    }

    fn write_legacy_fixture(backend: &DemoBackend, password: &str, key_byte: u8) -> [u8; 20] {
        let private_key = Zeroizing::new([key_byte; KEY_BYTES]);
        let address = address_from_private_key(&private_key).expect("legacy fixture address");
        let sealed = seal_vault(&private_key, password).expect("seal legacy fixture");
        write_new_vault(&backend.vault_path, sealed.as_slice()).expect("write legacy fixture");
        address
    }

    #[test]
    fn generated_mnemonic_is_not_persisted_until_confirmation_and_opens_as_v2() {
        for words in [NewMnemonicWords::Twelve, NewMnemonicWords::TwentyFour] {
            let clock = TestClock::new(Instant::now());
            let mut backend = v2_backend(clock);
            let reveal = backend
                .begin_generate(words, sensitive(TEST_PASSWORD), sensitive(TEST_PASSWORD))
                .expect("begin generated mnemonic");
            assert!(!backend.vault_path.exists());
            assert!(!backend.vault_v2_path.exists());
            assert!(backend.pending_generation.is_some());
            drop(reveal);

            let snapshot = backend
                .confirm_generated()
                .expect("confirm generated mnemonic");
            let expected_words = match words {
                NewMnemonicWords::Twelve => 12,
                NewMnemonicWords::TwentyFour => 24,
            };
            assert!(
                snapshot.wallet_kind
                    == WalletKind::V2Mnemonic {
                        word_count: expected_words,
                    }
            );
            assert_eq!(snapshot.account_count, 2);
            assert!(backend.vault_v2_path.is_file());
            assert!(!backend.vault_path.exists());
            assert!(backend.pending_generation.is_none());
            assert!(matches!(backend.unlocked, Some(UnlockedWallet::V2(_))));

            let expected_address = snapshot.address;
            backend.lock();
            let reopened = backend.open(TEST_PASSWORD).expect("reopen generated v2");
            assert_eq!(reopened.address, expected_address);
            assert_eq!(reopened.account_count, 2);
            remove_test_backend_files(&backend);
        }
    }

    #[test]
    fn generated_mnemonic_cancel_and_backend_expiry_write_nothing() {
        let clock = TestClock::new(Instant::now());
        let mut cancelled = v2_backend(clock);
        let reveal = cancelled
            .begin_generate(
                NewMnemonicWords::Twelve,
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            )
            .expect("begin cancellable generation");
        drop(reveal);
        cancelled.cancel_generated();
        assert!(matches!(
            cancelled.confirm_generated(),
            Err(BackendError::NoPendingGeneration)
        ));
        assert!(!cancelled.vault_v2_path.exists());
        remove_test_backend_files(&cancelled);

        let clock = TestClock::new(Instant::now());
        let mut expired = v2_backend(clock.clone());
        drop(
            expired
                .begin_generate(
                    NewMnemonicWords::Twelve,
                    sensitive(TEST_PASSWORD),
                    sensitive(TEST_PASSWORD),
                )
                .expect("begin expiring generation"),
        );
        clock.advance(GENERATED_BACKUP_TTL);
        assert!(matches!(
            expired.confirm_generated(),
            Err(BackendError::GenerationExpired)
        ));
        assert!(expired.pending_generation.is_none());
        assert!(!expired.vault_v2_path.exists());
        remove_test_backend_files(&expired);
    }

    #[test]
    fn mnemonic_and_raw_import_validate_metadata_and_never_overwrite() {
        let generated = WalletSecret::generate_mnemonic(MnemonicWordCount::Twelve)
            .expect("generate import fixture");
        let (_, mut phrase) = generated
            .export_mnemonic()
            .expect("export import fixture")
            .into_zeroizing_text();
        let imported_phrase = SensitiveText::new(std::mem::take(&mut *phrase));
        let mut mnemonic_backend = v2_backend(TestClock::new(Instant::now()));
        let snapshot = mnemonic_backend
            .import_mnemonic(
                imported_phrase,
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            )
            .expect("import mnemonic");
        assert_eq!(snapshot.account_count, 2);
        assert!(matches!(
            snapshot.wallet_kind,
            WalletKind::V2Mnemonic { word_count: 12 }
        ));
        assert!(matches!(
            mnemonic_backend.import_private_key(
                SensitiveText::new("11".repeat(KEY_BYTES)),
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            ),
            Err(BackendError::AlreadyExists)
        ));
        remove_test_backend_files(&mnemonic_backend);

        let mut raw_backend = v2_backend(TestClock::new(Instant::now()));
        let snapshot = raw_backend
            .import_private_key(
                SensitiveText::new("22".repeat(KEY_BYTES)),
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            )
            .expect("import raw key");
        assert!(snapshot.wallet_kind == WalletKind::V2RawPrivateKey);
        assert_eq!(snapshot.account_count, 1);
        assert!(matches!(
            raw_backend.export_mnemonic_inner(sensitive(TEST_PASSWORD)),
            Err(BackendError::MnemonicUnavailable)
        ));
        assert!(
            raw_backend
                .export_account_private_key_inner(sensitive(TEST_PASSWORD))
                .is_ok()
        );
        remove_test_backend_files(&raw_backend);
    }

    #[test]
    fn v2_open_never_falls_back_to_legacy_and_export_requires_reauthentication() {
        let mut backend = v2_backend(TestClock::new(Instant::now()));
        drop(
            backend
                .begin_generate(
                    NewMnemonicWords::Twelve,
                    sensitive(TEST_PASSWORD),
                    sensitive(TEST_PASSWORD),
                )
                .expect("begin v2 fixture"),
        );
        let snapshot = backend.confirm_generated().expect("persist v2 fixture");
        let legacy_password = "legacy demo password";
        write_legacy_fixture(&backend, legacy_password, 3);
        backend.lock();
        assert!(matches!(
            backend.open(legacy_password),
            Err(BackendError::VaultAuthentication)
        ));
        let reopened = backend.open(TEST_PASSWORD).expect("open preferred v2");
        assert_eq!(reopened.address, snapshot.address);
        assert!(matches!(
            backend.export_mnemonic_inner(sensitive(legacy_password)),
            Err(BackendError::VaultAuthentication)
        ));
        assert!(
            backend
                .export_mnemonic_inner(sensitive(TEST_PASSWORD))
                .is_ok()
        );
        remove_test_backend_files(&backend);
    }

    #[test]
    fn legacy_migration_reauthenticates_preserves_address_and_removes_v1() {
        let mut backend = v2_backend(TestClock::new(Instant::now()));
        let legacy_address = write_legacy_fixture(&backend, TEST_PASSWORD, 4);
        let expected = checksum_address(legacy_address);
        assert!(matches!(
            backend.migrate_legacy(
                sensitive("wrong legacy password"),
                sensitive("new migration password"),
                sensitive("new migration password"),
            ),
            Err(BackendError::VaultAuthentication)
        ));
        assert!(!backend.vault_v2_path.exists());
        assert!(backend.vault_path.is_file());

        let snapshot = backend
            .migrate_legacy(
                sensitive(TEST_PASSWORD),
                sensitive("new migration password"),
                sensitive("new migration password"),
            )
            .expect("migrate legacy v1");
        assert_eq!(snapshot.address, expected);
        assert!(snapshot.wallet_kind == WalletKind::V2RawPrivateKey);
        assert_eq!(snapshot.account_count, 1);
        assert!(backend.vault_v2_path.is_file());
        assert!(!backend.vault_path.exists());
        backend.lock();
        assert_eq!(
            backend
                .open("new migration password")
                .expect("open migrated v2")
                .address,
            expected
        );
        remove_test_backend_files(&backend);
    }

    #[test]
    fn pending_broadcast_blocks_every_wallet_management_mutation() {
        let mut backend = v2_backend(TestClock::new(Instant::now()));
        write_new_file(&backend.pending_path, b"pending quarantine sentinel")
            .expect("write pending sentinel");
        assert!(matches!(
            backend.begin_generate(
                NewMnemonicWords::Twelve,
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            ),
            Err(BackendError::PendingExists)
        ));
        assert!(matches!(
            backend.import_private_key(
                SensitiveText::new("33".repeat(KEY_BYTES)),
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            ),
            Err(BackendError::PendingExists)
        ));
        assert!(!backend.vault_v2_path.exists());
        remove_test_backend_files(&backend);

        let mut migration = v2_backend(TestClock::new(Instant::now()));
        write_legacy_fixture(&migration, TEST_PASSWORD, 5);
        write_new_file(&migration.pending_path, b"pending quarantine sentinel")
            .expect("write migration pending sentinel");
        assert!(matches!(
            migration.migrate_legacy(
                sensitive(TEST_PASSWORD),
                sensitive("new migration password"),
                sensitive("new migration password"),
            ),
            Err(BackendError::PendingExists)
        ));
        assert!(migration.vault_path.is_file());
        assert!(!migration.vault_v2_path.exists());
        remove_test_backend_files(&migration);
    }

    #[test]
    fn non_regular_pending_and_v2_entries_fail_closed() {
        let mut pending = v2_backend(TestClock::new(Instant::now()));
        fs::create_dir_all(&pending.pending_path).expect("create non-regular pending entry");
        assert!(pending.pending_broadcast_exists());
        assert!(matches!(
            pending.begin_generate(
                NewMnemonicWords::Twelve,
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            ),
            Err(BackendError::PendingExists)
        ));
        fs::remove_dir(&pending.pending_path).expect("remove pending directory fixture");
        remove_test_backend_files(&pending);

        let mut selector = v2_backend(TestClock::new(Instant::now()));
        write_legacy_fixture(&selector, TEST_PASSWORD, 6);
        fs::create_dir(&selector.vault_v2_path).expect("create non-regular v2 entry");
        assert!(matches!(
            selector.open(TEST_PASSWORD),
            Err(BackendError::VaultInvalid)
        ));
        assert!(selector.unlocked.is_none());
        fs::remove_dir(&selector.vault_v2_path).expect("remove v2 directory fixture");
        remove_test_backend_files(&selector);
    }

    #[test]
    fn vault_round_trip_and_wrong_password_collapse() {
        let private_key = [7_u8; 32];
        let sealed = seal_vault(&private_key, TEST_PASSWORD).expect("seal test vault");
        assert_eq!(sealed.len(), VAULT_FILE_BYTES);
        let opened = open_vault(sealed.as_slice(), TEST_PASSWORD).expect("open test vault");
        assert_eq!(opened.as_ref(), &private_key);
        assert!(matches!(
            open_vault(sealed.as_slice(), "incorrect demo password"),
            Err(BackendError::VaultAuthentication)
        ));
    }

    #[test]
    fn vault_rejects_tampering_truncation_and_wrong_chain_binding() {
        let sealed = seal_vault(&[8_u8; 32], TEST_PASSWORD).expect("seal test vault");
        for length in [0, VAULT_HEADER_BYTES - 1, VAULT_FILE_BYTES - 1] {
            assert!(matches!(
                open_vault(&sealed[..length], TEST_PASSWORD),
                Err(BackendError::VaultInvalid)
            ));
        }
        let mut wrong_chain = sealed.to_vec();
        wrong_chain[95] = 1;
        assert!(matches!(
            open_vault(&wrong_chain, TEST_PASSWORD),
            Err(BackendError::VaultInvalid)
        ));
        let mut ciphertext = sealed.to_vec();
        ciphertext[VAULT_FILE_BYTES - 1] ^= 1;
        assert!(matches!(
            open_vault(&ciphertext, TEST_PASSWORD),
            Err(BackendError::VaultAuthentication)
        ));
    }

    #[test]
    fn create_refuses_to_overwrite_and_can_reopen() {
        let vault = temporary_vault();
        let mut backend = DemoBackend::with_rpc(vault.clone(), test_rpc());
        let created = backend.create(TEST_PASSWORD).expect("create wallet");
        assert!(created.address.starts_with("0x"));
        assert_eq!(created.balance_eth, "0");
        assert!(matches!(
            backend.create(TEST_PASSWORD),
            Err(BackendError::AlreadyExists)
        ));
        backend.lock();
        let reopened = backend.open(TEST_PASSWORD).expect("reopen wallet");
        assert_eq!(reopened.address, created.address);
        let _ = fs::remove_file(&vault);
        if let Some(parent) = vault.parent() {
            let _ = fs::remove_dir(parent);
        }
    }

    #[test]
    fn final_path_claim_allows_exactly_one_concurrent_writer() {
        use std::sync::{Arc, Barrier};

        let vault = temporary_vault();
        let first = [0x11_u8; VAULT_FILE_BYTES];
        let second = [0x22_u8; VAULT_FILE_BYTES];
        let start = Arc::new(Barrier::new(3));
        let first_path = vault.clone();
        let second_path = vault.clone();
        let first_start = Arc::clone(&start);
        let second_start = Arc::clone(&start);

        let (first_result, second_result) = std::thread::scope(|scope| {
            let first_writer = scope.spawn(move || {
                first_start.wait();
                write_new_vault(&first_path, &first)
            });
            let second_writer = scope.spawn(move || {
                second_start.wait();
                write_new_vault(&second_path, &second)
            });
            start.wait();
            (
                first_writer.join().expect("first writer did not panic"),
                second_writer.join().expect("second writer did not panic"),
            )
        });

        assert_eq!(
            usize::from(first_result.is_ok()) + usize::from(second_result.is_ok()),
            1
        );
        assert_eq!(
            usize::from(matches!(first_result, Err(BackendError::AlreadyExists)))
                + usize::from(matches!(second_result, Err(BackendError::AlreadyExists))),
            1
        );
        let stored = fs::read(&vault).expect("winning record is readable");
        assert!(stored == first || stored == second);

        let _ = fs::remove_file(&vault);
        if let Some(parent) = vault.parent() {
            let _ = fs::remove_dir(parent);
        }
    }

    #[test]
    fn durable_record_creation_and_deletion_flush_the_real_parent_directory() {
        let vault = temporary_vault();
        let pending = vault.with_file_name("pending-v1.bin");
        write_new_file(&pending, b"directory durability probe")
            .expect("create and flush durable record");
        assert_eq!(
            fs::read(&pending).expect("read durable record"),
            b"directory durability probe"
        );

        remove_pending(&pending).expect("delete and flush durable record");
        assert!(!pending.exists());
        if let Some(parent) = pending.parent() {
            let _ = fs::remove_dir(parent);
        }
    }

    #[test]
    fn preview_binds_exact_fields_and_confirmation_signs_only_that_object() {
        let vault = temporary_vault();
        let mut backend = DemoBackend::with_rpc(vault.clone(), test_rpc());
        let created = backend.create(TEST_PASSWORD).expect("create wallet");
        let mut recipient_input = "0x1111111111111111111111111111111111111111".to_owned();
        let mut amount_input = "0.25".to_owned();
        let mut preview = backend
            .prepare_transfer_inner(&recipient_input, &amount_input, FeeSelection::Recommended)
            .expect("prepare native transfer");
        assert_eq!(preview.recipient, checksum_address([0x11; 20]));
        assert_eq!(preview.amount_eth, "0.25");
        assert_eq!(preview.nonce, "7");
        assert_eq!(preview.fee_mode_ko, "추천");
        assert_eq!(preview.gas_limit, "21000");
        assert_eq!(preview.quoted_base_fee_per_gas_gwei, "0.5");
        assert_eq!(preview.max_priority_fee_per_gas_gwei, "1");
        assert_eq!(preview.max_fee_per_gas_gwei, "2");
        assert_eq!(preview.estimated_network_fee_eth, "0.0000315");
        assert_eq!(preview.max_network_fee_eth, "0.000042");
        assert_eq!(preview.estimated_total_eth, "0.2500315");
        assert_eq!(preview.max_total_eth, "0.250042");
        let remaining_seconds = preview
            .quote_valid_for_seconds
            .parse::<u64>()
            .expect("remaining quote seconds");
        assert!(
            (MIN_CONFIRMABLE_QUOTE_SECONDS..=FEE_QUOTE_TTL.as_secs()).contains(&remaining_seconds)
        );
        assert!(!backend.pending_broadcast_exists());

        let prepared = backend.prepared.as_ref().expect("prepared object");
        let expected = sign_native_type_two(
            backend
                .unlocked
                .as_ref()
                .expect("unlocked wallet")
                .legacy_private_key_for_test(),
            prepared.sender,
            prepared.recipient,
            prepared.value,
            prepared.nonce,
            prepared.gas_limit,
            prepared.priority_fee,
            prepared.maximum_fee,
        )
        .expect("expected deterministic signature")
        .transaction_hash;

        recipient_input.clear();
        recipient_input.push_str("0x2222222222222222222222222222222222222222");
        amount_input.clear();
        amount_input.push('1');
        preview.recipient = checksum_address([0x22; 20]);
        preview.amount_eth = "1".to_owned();
        preview.nonce = "999".to_owned();
        preview.fee_mode_ko = "직접 입력".to_owned();
        preview.gas_limit = "999".to_owned();
        preview.quoted_base_fee_per_gas_gwei = "99".to_owned();
        preview.max_priority_fee_per_gas_gwei = "9".to_owned();
        preview.max_fee_per_gas_gwei = "99".to_owned();
        preview.estimated_network_fee_eth = "8".to_owned();
        preview.max_network_fee_eth = "9".to_owned();
        preview.estimated_total_eth = "9".to_owned();
        preview.max_total_eth = "10".to_owned();
        preview.quote_valid_for_seconds = "999".to_owned();
        assert_eq!(preview.nonce, "999");
        let receipt = backend
            .confirm_prepared_inner()
            .expect("confirm exact prepared transfer");
        assert_eq!(receipt.transaction_hash, fixed_hex(&expected));
        assert!(receipt.transaction_hash.starts_with("0x"));
        assert_eq!(receipt.transaction_hash.len(), 66);
        assert_eq!(backend.address().as_deref(), Some(created.address.as_str()));
        assert!(backend.prepared.is_none());
        assert_eq!(
            recipient_input,
            "0x2222222222222222222222222222222222222222"
        );
        assert_eq!(amount_input, "1");
        let _ = fs::remove_file(&vault);
        if let Some(parent) = vault.parent() {
            let _ = fs::remove_dir(parent);
        }
    }

    #[test]
    fn faster_and_custom_modes_freeze_exact_integer_fees_and_costs() {
        let recipient = "0x1111111111111111111111111111111111111111";

        let faster_rpc = MutableRpc::new();
        let faster_clock = TestClock::new(Instant::now());
        let mut faster = unlocked_backend(faster_rpc, faster_clock);
        let faster_preview = faster
            .prepare_transfer_inner(recipient, "0.25", FeeSelection::Faster)
            .expect("prepare faster transfer");
        assert_eq!(faster_preview.fee_mode_ko, "빠르게");
        assert_eq!(faster_preview.quoted_base_fee_per_gas_gwei, "0.5");
        assert_eq!(faster_preview.max_priority_fee_per_gas_gwei, "2");
        assert_eq!(faster_preview.max_fee_per_gas_gwei, "3");
        assert_eq!(faster_preview.estimated_network_fee_eth, "0.0000525");
        assert_eq!(faster_preview.max_network_fee_eth, "0.000063");
        assert_eq!(faster_preview.estimated_total_eth, "0.2500525");
        assert_eq!(faster_preview.max_total_eth, "0.250063");
        assert!(
            faster
                .prepared
                .as_ref()
                .map(|prepared| prepared.priority_fee)
                == Some(Word::from_u64(2_000_000_000))
        );
        remove_test_backend_files(&faster);

        let custom_rpc = MutableRpc::new();
        let custom_clock = TestClock::new(Instant::now());
        let mut custom = unlocked_backend(custom_rpc, custom_clock);
        let custom_preview = custom
            .prepare_transfer_inner(
                recipient,
                "0.25",
                FeeSelection::Custom {
                    max_priority_fee_per_gas_gwei: "1.25".to_owned(),
                    max_fee_per_gas_gwei: "3.5".to_owned(),
                },
            )
            .expect("prepare custom transfer");
        assert_eq!(custom_preview.fee_mode_ko, "직접 입력");
        assert_eq!(custom_preview.max_priority_fee_per_gas_gwei, "1.25");
        assert_eq!(custom_preview.max_fee_per_gas_gwei, "3.5");
        assert_eq!(custom_preview.estimated_network_fee_eth, "0.00003675");
        assert_eq!(custom_preview.max_network_fee_eth, "0.0000735");
        assert_eq!(custom_preview.estimated_total_eth, "0.25003675");
        assert_eq!(custom_preview.max_total_eth, "0.2500735");
        assert_eq!(custom_preview.gas_limit, "21000");
        remove_test_backend_files(&custom);
    }

    #[test]
    fn custom_gwei_parser_and_fee_caps_are_exact() {
        assert!(parse_gwei("0").expect("zero gwei") == Word::ZERO);
        assert!(
            parse_gwei("1.000000001").expect("one wei precision") == Word::from_u64(1_000_000_001)
        );
        assert!(
            parse_gwei("0001.250000000").expect("leading zero normalization")
                == Word::from_u64(1_250_000_000)
        );
        assert!(
            parse_gwei("100").expect("maximum fee cap shape") == Word::from_u64(MAX_FEE_PER_GAS)
        );
        for invalid in [
            "",
            ".1",
            "1.",
            " 1",
            "1 ",
            "+1",
            "-1",
            "1e2",
            "1,0",
            "1\n",
            "1.0000000001",
            "111111111111111111111111111111111",
        ] {
            assert!(parse_gwei(invalid).is_err(), "invalid Gwei shape");
        }

        let quote = NetworkFeeQuote {
            base_fee: Word::from_u64(1_000_000_000),
            recommended_priority_fee: Word::from_u64(1_000_000_000),
            recommended_maximum_fee: Word::from_u64(3_000_000_000),
        };
        assert!(
            resolve_fee_plan(
                FeeSelection::Custom {
                    max_priority_fee_per_gas_gwei: "10".to_owned(),
                    max_fee_per_gas_gwei: "100".to_owned(),
                },
                quote,
            )
            .is_ok()
        );
        for (priority, maximum) in [("10.000000001", "100"), ("10", "100.000000001")] {
            assert!(matches!(
                resolve_fee_plan(
                    FeeSelection::Custom {
                        max_priority_fee_per_gas_gwei: priority.to_owned(),
                        max_fee_per_gas_gwei: maximum.to_owned(),
                    },
                    quote,
                ),
                Err(BackendError::FeeLimit)
            ));
        }
        for (priority, maximum) in [("2", "1"), ("1", "1.5")] {
            assert!(matches!(
                resolve_fee_plan(
                    FeeSelection::Custom {
                        max_priority_fee_per_gas_gwei: priority.to_owned(),
                        max_fee_per_gas_gwei: maximum.to_owned(),
                    },
                    quote,
                ),
                Err(BackendError::FeeCombination)
            ));
        }

        let zero_tip_quote = NetworkFeeQuote {
            base_fee: Word::from_u64(1_000_000_000),
            recommended_priority_fee: Word::ZERO,
            recommended_maximum_fee: Word::from_u64(2_000_000_000),
        };
        assert!(matches!(
            resolve_fee_plan(FeeSelection::Faster, zero_tip_quote),
            Err(BackendError::FasterUnavailable)
        ));
        let capped_tip_quote = NetworkFeeQuote {
            base_fee: Word::from_u64(1_000_000_000),
            recommended_priority_fee: Word::from_u64(MAX_PRIORITY_FEE_PER_GAS),
            recommended_maximum_fee: Word::from_u64(12_000_000_000),
        };
        assert!(matches!(
            resolve_fee_plan(FeeSelection::Faster, capped_tip_quote),
            Err(BackendError::FasterUnavailable)
        ));
    }

    #[test]
    fn every_backend_error_mapping_crosses_the_ui_allowlist_exactly() {
        let errors = [
            BackendError::StorageUnavailable,
            BackendError::AlreadyExists,
            BackendError::NotFound,
            BackendError::LegacyNotFound,
            BackendError::InvalidPassword,
            BackendError::PasswordMismatch,
            BackendError::VaultAuthentication,
            BackendError::VaultInvalid,
            BackendError::InvalidMnemonic,
            BackendError::InvalidPrivateKey,
            BackendError::WalletMetadataInvalid,
            BackendError::WalletChanged,
            BackendError::GenerationPending,
            BackendError::NoPendingGeneration,
            BackendError::GenerationExpired,
            BackendError::MigrationCleanup,
            BackendError::MnemonicUnavailable,
            BackendError::RandomnessUnavailable,
            BackendError::CryptographicFailure,
            BackendError::Locked,
            BackendError::RpcUnavailable,
            BackendError::BalanceUnavailable,
            BackendError::InvalidAddress,
            BackendError::InvalidAmount,
            BackendError::AmountLimit,
            BackendError::InvalidFeeInput,
            BackendError::FeeCombination,
            BackendError::FeeLimit,
            BackendError::FasterUnavailable,
            BackendError::QuoteExpired,
            BackendError::QuoteChanged,
            BackendError::AccountChanged,
            BackendError::UnsupportedTransfer,
            BackendError::InsufficientBalance,
            BackendError::BroadcastUnknown,
            BackendError::HashMismatch,
            BackendError::PendingExists,
            BackendError::PendingInvalid,
            BackendError::PendingCleanup,
            BackendError::NoPreparedTransfer,
            BackendError::PreparedInvalid,
        ];
        for error in errors {
            let mapped = error_text(error);
            assert_eq!(crate::ui::safe_error(mapped.clone()), mapped, "{error:?}");
        }
    }

    #[test]
    fn prepare_displays_conservative_remaining_seconds_and_requires_hold_margin() {
        let recipient = "0x1111111111111111111111111111111111111111";

        let elapsed_rpc = MutableRpc::new();
        let elapsed_clock = TestClock::new(Instant::now());
        elapsed_rpc.update(|state| {
            state.expire_clock_on_estimate_call =
                Some((elapsed_clock.clone(), 1, Duration::from_millis(7_500)));
        });
        let mut elapsed_backend = unlocked_backend(elapsed_rpc, elapsed_clock);
        let preview = elapsed_backend
            .prepare_transfer_inner(recipient, "0.25", FeeSelection::Recommended)
            .expect("prepare with elapsed RPC time");
        assert_eq!(preview.quote_valid_for_seconds, "52");
        remove_test_backend_files(&elapsed_backend);

        let three_second_rpc = MutableRpc::new();
        let three_second_clock = TestClock::new(Instant::now());
        three_second_rpc.update(|state| {
            state.expire_clock_on_estimate_call =
                Some((three_second_clock.clone(), 1, Duration::from_secs(57)));
        });
        let mut three_second_backend = unlocked_backend(three_second_rpc, three_second_clock);
        let preview = three_second_backend
            .prepare_transfer_inner(recipient, "0.25", FeeSelection::Recommended)
            .expect("three full remaining seconds leave room for the two-second hold");
        assert_eq!(preview.quote_valid_for_seconds, "3");
        remove_test_backend_files(&three_second_backend);

        for elapsed in [Duration::from_secs(58), FEE_QUOTE_TTL] {
            let rpc = MutableRpc::new();
            let clock = TestClock::new(Instant::now());
            rpc.update(|state| {
                state.expire_clock_on_estimate_call = Some((clock.clone(), 1, elapsed));
            });
            let mut backend = unlocked_backend(rpc.clone(), clock);
            assert!(matches!(
                backend.prepare_transfer_inner(recipient, "0.25", FeeSelection::Recommended,),
                Err(BackendError::QuoteExpired)
            ));
            assert!(backend.prepared.is_none());
            assert_eq!(backend.sign_attempts, 0);
            assert!(!backend.pending_broadcast_exists());
            let state = rpc.state.lock().expect("expired prepare RPC lock");
            assert_eq!(state.estimate_calls, 1);
            assert_eq!(state.balance_calls, 1);
            assert!(state.sent.is_empty());
            drop(state);
            remove_test_backend_files(&backend);
        }
    }

    #[test]
    fn quote_ttl_is_backend_owned_strict_and_checked_again_before_signing() {
        let (mut live_backend, live_rpc, live_clock) = prepared_mutable_backend();
        live_clock.advance(
            FEE_QUOTE_TTL
                .checked_sub(Duration::from_nanos(1))
                .expect("positive TTL"),
        );
        live_backend
            .confirm_prepared_inner()
            .expect("quote remains live just before deadline");
        assert_eq!(live_backend.sign_attempts, 1);
        assert_eq!(live_rpc.state.lock().expect("live RPC lock").sent.len(), 1);
        remove_test_backend_files(&live_backend);

        let (mut expired_backend, expired_rpc, expired_clock) = prepared_mutable_backend();
        expired_clock.advance(FEE_QUOTE_TTL);
        assert!(matches!(
            expired_backend.confirm_prepared_inner(),
            Err(BackendError::QuoteExpired)
        ));
        assert!(expired_backend.prepared.is_none());
        assert_eq!(expired_backend.sign_attempts, 0);
        assert!(!expired_backend.pending_broadcast_exists());
        let expired_state = expired_rpc.state.lock().expect("expired RPC lock");
        assert_eq!(expired_state.verify_calls, 1);
        assert!(expired_state.sent.is_empty());
        drop(expired_state);
        remove_test_backend_files(&expired_backend);

        let (mut final_backend, final_rpc, final_clock) = prepared_mutable_backend();
        final_rpc.update(|state| {
            state.expire_clock_on_estimate_call = Some((final_clock.clone(), 2, FEE_QUOTE_TTL));
        });
        assert!(matches!(
            final_backend.confirm_prepared_inner(),
            Err(BackendError::QuoteExpired)
        ));
        assert!(final_backend.prepared.is_none());
        assert_eq!(final_backend.sign_attempts, 0);
        assert!(!final_backend.pending_broadcast_exists());
        let final_state = final_rpc.state.lock().expect("final TTL RPC lock");
        assert_eq!(final_state.estimate_calls, 2);
        assert!(final_state.sent.is_empty());
        drop(final_state);
        remove_test_backend_files(&final_backend);
    }

    #[test]
    fn confirm_consumes_prepared_state_on_every_frozen_state_recheck_failure() {
        let (mut chain_backend, chain_rpc, _) = prepared_mutable_backend();
        chain_rpc.update(|state| state.verify_ok = false);
        assert!(matches!(
            chain_backend.confirm_prepared_inner(),
            Err(BackendError::RpcUnavailable)
        ));
        assert!(chain_backend.prepared.is_none());
        assert_eq!(chain_backend.sign_attempts, 0);
        assert!(!chain_backend.pending_broadcast_exists());
        remove_test_backend_files(&chain_backend);

        let (mut nonce_backend, nonce_rpc, _) = prepared_mutable_backend();
        nonce_rpc.update(|state| state.nonce = Word::from_u64(8));
        assert!(matches!(
            nonce_backend.confirm_prepared_inner(),
            Err(BackendError::AccountChanged)
        ));
        assert!(nonce_backend.prepared.is_none());
        assert_eq!(nonce_backend.sign_attempts, 0);
        assert!(!nonce_backend.pending_broadcast_exists());
        remove_test_backend_files(&nonce_backend);

        let (mut base_backend, base_rpc, _) = prepared_mutable_backend();
        base_rpc.update(|state| state.base_fee = Word::from_u64(1_500_000_000));
        assert!(matches!(
            base_backend.confirm_prepared_inner(),
            Err(BackendError::QuoteChanged)
        ));
        assert!(base_backend.prepared.is_none());
        assert_eq!(base_backend.sign_attempts, 0);
        assert!(!base_backend.pending_broadcast_exists());
        remove_test_backend_files(&base_backend);

        let (mut balance_backend, balance_rpc, _) = prepared_mutable_backend();
        balance_rpc.update(|state| state.balance = Word::from_u64(1));
        assert!(matches!(
            balance_backend.confirm_prepared_inner(),
            Err(BackendError::InsufficientBalance)
        ));
        assert!(balance_backend.prepared.is_none());
        assert_eq!(balance_backend.sign_attempts, 0);
        assert!(!balance_backend.pending_broadcast_exists());
        remove_test_backend_files(&balance_backend);

        let (mut gas_backend, gas_rpc, _) = prepared_mutable_backend();
        gas_rpc.update(|state| state.estimated_gas = Word::from_u64(21_001));
        assert!(matches!(
            gas_backend.confirm_prepared_inner(),
            Err(BackendError::UnsupportedTransfer)
        ));
        assert!(gas_backend.prepared.is_none());
        assert_eq!(gas_backend.sign_attempts, 0);
        assert!(!gas_backend.pending_broadcast_exists());
        let gas_state = gas_rpc.state.lock().expect("gas RPC lock");
        assert!(gas_state.sent.is_empty());
        drop(gas_state);
        remove_test_backend_files(&gas_backend);
    }

    #[test]
    fn prepare_rejects_any_native_transfer_estimate_other_than_exact_21000() {
        let rpc = MutableRpc::new();
        rpc.update(|state| state.estimated_gas = Word::from_u64(21_001));
        let clock = TestClock::new(Instant::now());
        let mut backend = unlocked_backend(rpc.clone(), clock);
        assert!(matches!(
            backend.prepare_transfer_inner(
                "0x1111111111111111111111111111111111111111",
                "0.25",
                FeeSelection::Recommended,
            ),
            Err(BackendError::UnsupportedTransfer)
        ));
        assert!(backend.prepared.is_none());
        assert_eq!(backend.sign_attempts, 0);
        assert!(!backend.pending_broadcast_exists());
        let state = rpc.state.lock().expect("prepare gas RPC lock");
        assert_eq!(state.estimate_calls, 1);
        assert_eq!(state.balance_calls, 0);
        assert!(state.sent.is_empty());
        drop(state);
        remove_test_backend_files(&backend);
    }

    #[test]
    fn confirm_never_reprices_and_persists_before_mock_broadcast() {
        let (mut backend, rpc, _) = prepared_mutable_backend();
        let prepared = backend.prepared.as_ref().expect("prepared transfer");
        let expected = sign_native_type_two(
            backend
                .unlocked
                .as_ref()
                .expect("unlocked wallet")
                .legacy_private_key_for_test(),
            prepared.sender,
            prepared.recipient,
            prepared.value,
            prepared.nonce,
            prepared.gas_limit,
            prepared.priority_fee,
            prepared.maximum_fee,
        )
        .expect("expected frozen signature")
        .transaction_hash;
        let pending_path = backend.pending_path.clone();
        rpc.update(|state| {
            state.priority = Word::from_u64(9_000_000_000);
            state.maximum = Word::from_u64(99_000_000_000);
            state.pending_path_to_require = Some(pending_path);
        });

        let receipt = backend
            .confirm_prepared_inner()
            .expect("confirm frozen transfer");
        assert_eq!(receipt.transaction_hash, fixed_hex(&expected));
        assert_eq!(backend.sign_attempts, 1);
        let state = rpc.state.lock().expect("no repricing RPC lock");
        assert_eq!(state.quote_calls, 1);
        assert_eq!(state.nonce_calls, 2);
        assert_eq!(state.estimate_calls, 2);
        assert_eq!(state.sent.len(), 1);
        assert!(state.send_observed_pending);
        drop(state);
        remove_test_backend_files(&backend);
    }

    #[test]
    fn ambiguous_pending_retry_reuses_exact_bytes_without_quote_nonce_or_signing() {
        let (mut backend, rpc, _) = prepared_mutable_backend();
        let pending_path = backend.pending_path.clone();
        rpc.update(|state| {
            state.send_fails = true;
            state.pending_path_to_require = Some(pending_path);
        });
        assert!(matches!(
            backend.confirm_prepared_inner(),
            Err(BackendError::BroadcastUnknown)
        ));
        assert!(backend.pending_broadcast_exists());
        assert_eq!(backend.sign_attempts, 1);
        let (raw, quote_calls, nonce_calls, estimate_calls) = {
            let state = rpc.state.lock().expect("first pending RPC lock");
            assert_eq!(state.sent.len(), 1);
            assert!(state.send_observed_pending);
            (
                state.sent[0].clone(),
                state.quote_calls,
                state.nonce_calls,
                state.estimate_calls,
            )
        };
        rpc.update(|state| state.send_fails = false);

        backend
            .retry_pending_inner()
            .expect("retry exact persisted bytes");
        assert_eq!(backend.sign_attempts, 1);
        let state = rpc.state.lock().expect("retry pending RPC lock");
        assert_eq!(state.sent.len(), 2);
        assert_eq!(state.sent[1], raw);
        assert_eq!(state.quote_calls, quote_calls);
        assert_eq!(state.nonce_calls, nonce_calls);
        assert_eq!(state.estimate_calls, estimate_calls);
        drop(state);
        assert!(!backend.pending_broadcast_exists());
        remove_test_backend_files(&backend);
    }

    #[test]
    fn ambiguous_broadcast_blocks_new_signing_and_exact_retry_clears_it() {
        let vault = temporary_vault();
        let pending = vault.with_file_name("pending-v1.bin");
        let mut failing_rpc = test_rpc();
        failing_rpc.send_fails = true;
        let mut backend = DemoBackend::with_rpc(vault.clone(), failing_rpc);
        backend.create(TEST_PASSWORD).expect("create wallet");
        let recipient = "0x1111111111111111111111111111111111111111";
        backend
            .prepare_transfer_inner(recipient, "0.25", FeeSelection::Recommended)
            .expect("prepare transfer");
        assert!(matches!(
            backend.confirm_prepared_inner(),
            Err(BackendError::BroadcastUnknown)
        ));
        assert!(backend.pending_broadcast_exists());
        assert!(matches!(
            backend.prepare_transfer_inner(recipient, "0.25", FeeSelection::Recommended),
            Err(BackendError::PendingExists)
        ));
        drop(backend);

        let mut reopened = DemoBackend::with_rpc(vault.clone(), test_rpc());
        reopened.open(TEST_PASSWORD).expect("reopen wallet");
        let receipt = reopened.retry_pending_inner().expect("retry exact bytes");
        assert_eq!(receipt.transaction_hash.len(), 66);
        assert!(!pending.exists());
        let _ = fs::remove_file(&vault);
        if let Some(parent) = vault.parent() {
            let _ = fs::remove_dir(parent);
        }
    }

    #[test]
    fn zero_y_parity_uses_canonical_rlp_empty_integer() {
        assert_eq!(rlp_integer(&[0]), vec![0x80]);
        assert_eq!(rlp_integer(&[1]), vec![0x01]);
    }

    #[test]
    fn zero_priority_fallback_is_valid_but_zero_maximum_fee_is_not() {
        assert!(validate_fee_quote(Word::ZERO, Word::from_u64(1)).is_ok());
        assert!(validate_fee_quote(Word::ZERO, Word::ZERO).is_err());
    }

    #[test]
    fn cancellation_and_failed_reprepare_leave_nothing_confirmable() {
        let vault = temporary_vault();
        let mut backend = DemoBackend::with_rpc(vault.clone(), test_rpc());
        backend.create(TEST_PASSWORD).expect("create wallet");
        backend
            .prepare_transfer_inner(
                "0x1111111111111111111111111111111111111111",
                "0.25",
                FeeSelection::Recommended,
            )
            .expect("prepare transfer");
        backend.cancel_prepared_inner();
        assert!(matches!(
            backend.confirm_prepared_inner(),
            Err(BackendError::NoPreparedTransfer)
        ));

        backend
            .prepare_transfer_inner(
                "0x1111111111111111111111111111111111111111",
                "0.25",
                FeeSelection::Recommended,
            )
            .expect("prepare again");
        assert!(
            backend
                .prepare_transfer_inner("invalid", "1", FeeSelection::Recommended)
                .is_err()
        );
        assert!(backend.prepared.is_none());
        assert!(matches!(
            backend.confirm_prepared_inner(),
            Err(BackendError::NoPreparedTransfer)
        ));
        let _ = fs::remove_file(&vault);
        if let Some(parent) = vault.parent() {
            let _ = fs::remove_dir(parent);
        }
    }

    #[test]
    fn amount_parser_is_exact_and_formatter_round_trips_common_values() {
        assert_eq!(
            format_ether(parse_ether("1.25").expect("valid amount")),
            "1.25"
        );
        assert_eq!(
            format_ether(parse_ether("0.000000000000000001").expect("one wei")),
            "0.000000000000000001"
        );
        for invalid in ["", "01", ".1", "1.", "1e2", "-1", "0.0000000000000000001"] {
            assert!(parse_ether(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn address_parser_accepts_valid_checksum_and_rejects_burn_or_bad_checksum() {
        let key = [9_u8; 32];
        let address = address_from_private_key(&key).expect("derive address");
        let checksummed = checksum_address(address);
        assert_eq!(
            parse_address(&checksummed).expect("valid checksum"),
            address
        );
        assert!(parse_address("0x0000000000000000000000000000000000000000").is_err());
        let mut wrong = checksummed;
        if let Some(index) = wrong
            .bytes()
            .enumerate()
            .skip(2)
            .find(|(_, byte)| byte.is_ascii_alphabetic())
            .map(|(index, _)| index)
        {
            let byte = wrong.as_bytes()[index];
            wrong.replace_range(
                index..=index,
                &char::from(if byte.is_ascii_uppercase() {
                    byte.to_ascii_lowercase()
                } else {
                    byte.to_ascii_uppercase()
                })
                .to_string(),
            );
            assert!(parse_address(&wrong).is_err());
        }
    }
}
