//! Secret-bearing backend for the standalone Sepolia development wallet.
//!
//! This module is deliberately independent from the production vault and
//! authorization formats. It supports one fixed testnet, a v2 mnemonic/raw-key
//! vault with a guarded legacy-v1 migration path, native EIP-1559 transfers,
//! and exact `transfer(address,uint256)` calls for authenticated saved ERC-20s.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
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
use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    CreateFileW, DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_RENAME_INFO, FILE_SHARE_MODE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FileDispositionInfo, FileRenameInfo, FlushFileBuffers,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW, OPEN_EXISTING,
    SetFileInformationByHandle,
};
#[cfg(windows)]
use windows::core::PCWSTR;
use zeroize::{Zeroize, Zeroizing};

use crate::activity_store::{
    ACTIVITY_CAPACITY, ACTIVITY_FILE_BYTES, ActivityEntry, ActivityMutation, ActivityStatus,
    ActivityStore, ActivityStoreError, Inclusion, InclusionOutcome, ObservationCounters,
    TransactionIdentity, Transfer,
};
use crate::erc20::{self, TokenAmount};
use crate::rpc;
use crate::token_store::{TokenEntry, TokenStore, TokenStoreError};
use crate::ui::{
    ActivityInclusionOutcome, ActivityInclusionSnapshot, ActivityStatusSnapshot,
    ActivityTransferSnapshot, CustomTokenSnapshot, CustomTokenState, Erc20TransferPreview,
    FeeSelection, GeneratedBackupChallenge, GeneratedBackupConfirmation, GeneratedBackupReveal,
    NewMnemonicWords, PendingBroadcastPreview, SecretReveal, SecretRevealKind, SendReceipt,
    SensitiveText, SessionPermit, TransactionActivitySnapshot, TransferPreview,
    WalletAccountSnapshot, WalletBackend, WalletKind, WalletSnapshot,
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
const MIN_ERC20_TRANSFER_GAS_LIMIT: u64 = 25_200;
const MAX_ERC20_TRANSFER_GAS_LIMIT: u64 = 500_000;
const MAX_TRANSFER_WEI: u64 = 10_000_000_000_000_000_000;
const MAX_PRIORITY_FEE_PER_GAS: u64 = 10_000_000_000;
const MAX_FEE_PER_GAS: u64 = 100_000_000_000;
const FEE_QUOTE_TTL: Duration = Duration::from_secs(60);
const MIN_CONFIRMABLE_QUOTE_SECONDS: u64 = 3;
const MAX_GWEI_INPUT_BYTES: usize = 32;
const GENERATED_BACKUP_TTL: Duration = Duration::from_secs(120);
const MAX_RANDOM_SAMPLES: usize = 256;
const GENERATED_BACKUP_CHALLENGE_WORDS: usize = 4;
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
const MAX_TOKEN_STORE_BYTES: usize = 4_096;
static TOKEN_STORE_PROCESS_LOCK: Mutex<()> = Mutex::new(());
static ACTIVITY_STORE_PROCESS_LOCK: Mutex<()> = Mutex::new(());
#[cfg(not(windows))]
static LEGACY_MIGRATION_PROCESS_LOCK: Mutex<()> = Mutex::new(());

/// Concrete backend used by the native UI.
///
/// It intentionally has no `Debug` implementation because it owns the unlocked
/// private key and a local vault path.
pub struct DemoBackend {
    /// Legacy v1 path retained solely for authenticated migration/open.
    vault_path: PathBuf,
    vault_v2_path: PathBuf,
    pending_path: PathBuf,
    token_store_path: PathBuf,
    activity_store_path: PathBuf,
    rpc: Box<dyn RpcAccess>,
    unlocked: Option<UnlockedWallet>,
    selected_account_index: u8,
    pending_generation: Option<PendingGeneratedWallet>,
    last_balance: Option<AccountBalance>,
    prepared: Option<PreparedTransfer>,
    prepared_pending_retry: Option<PreparedPendingRetry>,
    clock: Box<dyn MonotonicClock>,
    #[cfg(test)]
    sign_attempts: usize,
    #[cfg(test)]
    fail_activity_persist_for_test: bool,
}

enum UnlockedWallet {
    LegacyV1 {
        private_key: Zeroizing<[u8; KEY_BYTES]>,
        address: [u8; 20],
    },
    V2(OpenedVaultV2),
}

/// One cached public balance bound to the exact selected account identity.
/// Keeping the index and address prevents a successful account switch from
/// rendering a value observed for the prior account.
struct AccountBalance {
    account_index: u8,
    address: [u8; 20],
    value: Word,
}

struct PendingGeneratedWallet {
    wallet: WalletSecret,
    password: VaultPassword,
    expires_at: Instant,
    stage: PendingGeneratedStage,
}

enum PendingGeneratedStage {
    Display,
    Challenge {
        positions: [u8; GENERATED_BACKUP_CHALLENGE_WORDS],
    },
}

impl UnlockedWallet {
    fn validated_metadata(&self) -> Result<([u8; 20], WalletKind, u8), BackendError> {
        match self {
            Self::LegacyV1 { address, .. } => Ok((*address, WalletKind::LegacyV1RawPrivateKey, 1)),
            Self::V2(opened) => validated_wallet_metadata(opened.wallet()),
        }
    }

    fn account_address(&self, index: u8) -> Result<[u8; 20], BackendError> {
        let (_, _, account_count) = self.validated_metadata()?;
        if index >= account_count {
            return Err(BackendError::UnsupportedAccount);
        }
        match self {
            Self::LegacyV1 { address, .. } if index == 0 => Ok(*address),
            Self::LegacyV1 { .. } => Err(BackendError::UnsupportedAccount),
            Self::V2(opened) => {
                let account = opened
                    .wallet()
                    .account(usize::from(index))
                    .ok_or(BackendError::UnsupportedAccount)?;
                let expected_index = u32::from(index);
                if account.requested_index() != expected_index
                    || account.actual_index() != expected_index
                {
                    return Err(BackendError::WalletMetadataInvalid);
                }
                Ok(*account.address().as_bytes())
            }
        }
    }

    fn account_snapshots(&self) -> Result<Vec<WalletAccountSnapshot>, BackendError> {
        let (_, _, account_count) = self.validated_metadata()?;
        let mut accounts = Vec::with_capacity(usize::from(account_count));
        for index in 0..account_count {
            accounts.push(WalletAccountSnapshot {
                index,
                address: checksum_address(self.account_address(index)?),
            });
        }
        Ok(accounts)
    }
}

/// Exact, signer-ready Sepolia fields fixed at preview time.
///
/// This value is neither `Clone` nor public. Confirmation consumes it before
/// any private-key operation, so edited UI strings cannot alter signed fields.
enum PreparedTransfer {
    Native(PreparedNativeTransfer),
    SavedErc20(PreparedErc20Transfer),
}

/// Exact pending-v1 bytes frozen only after canonical signature recovery and
/// bounded-wallet attribution. It is move-only, non-Debug, and its byte buffer
/// is zeroized when a lock, stale authorization, mismatch, or retry drops it.
struct PreparedPendingRetry {
    sender_account_index: u8,
    sender: [u8; 20],
    transaction_hash: [u8; 32],
    raw_transaction: Zeroizing<Vec<u8>>,
    lease: PendingFileLease,
}

impl PreparedPendingRetry {
    fn preview(&self) -> PendingBroadcastPreview {
        PendingBroadcastPreview {
            sender_account_index: self.sender_account_index,
            sender_address: checksum_address(self.sender),
            transaction_hash: fixed_hex(&self.transaction_hash),
        }
    }
}

struct PreparedNativeTransfer {
    account_index: u8,
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

/// Exact saved-token transfer facts frozen after authenticated sidecar and
/// full pending-chain bookends. This is neither `Clone` nor public.
struct PreparedErc20Transfer {
    account_index: u8,
    sender: [u8; 20],
    recipient: [u8; 20],
    contract: [u8; 20],
    amount: TokenAmount,
    saved_entry: TokenEntry,
    token_store_baseline: TokenStoreBaseline,
    nonce: Word,
    estimated_gas: u64,
    gas_limit: Word,
    quoted_base_fee: Word,
    priority_fee: Word,
    maximum_fee: Word,
    estimated_network_fee: Word,
    maximum_network_fee: Word,
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

/// Ephemeral v2-only context for the authenticated token sidecar.
///
/// This deliberately has no `Debug` implementation because it carries the
/// domain-separated sidecar key.
struct TokenContext {
    account_index: u8,
    owner: [u8; 20],
    vault_id: [u8; 16],
    key: Zeroizing<[u8; 32]>,
}

/// Ephemeral v2-only context for the independently keyed activity sidecar.
/// It has no `Debug` implementation because it owns derived key material.
struct ActivityContext {
    vault_id: [u8; 16],
    key: Zeroizing<[u8; 32]>,
}

struct LoadedActivityStore {
    store: ActivityStore,
    baseline: ActivityStoreBaseline,
}

struct ActivityStoreBaseline {
    bytes: Option<Vec<u8>>,
    generation: u64,
}

/// Serializes one full activity transaction from its pre-sign capacity
/// baseline through durable authenticated readback and exact pending cleanup.
struct ActivityMutationLease<'a> {
    _process_guard: MutexGuard<'a, ()>,
    activity_store_path: PathBuf,
    #[cfg(windows)]
    _lock_file: File,
    #[cfg(windows)]
    _parent_directory: DurableParentDirectory,
}

impl<'a> ActivityMutationLease<'a> {
    fn acquire(activity_store_path: &Path) -> Result<Self, BackendError> {
        let process_guard = ACTIVITY_STORE_PROCESS_LOCK
            .lock()
            .map_err(|_| BackendError::ActivityStoreStorage)?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;

            let parent = activity_store_path
                .parent()
                .ok_or(BackendError::ActivityStoreStorage)?;
            let parent_directory = DurableParentDirectory::open(parent)
                .map_err(|_| BackendError::ActivityStoreStorage)?;
            let lock_path = activity_store_lock_path(activity_store_path)?;
            let lock_file = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .share_mode(0)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
                .open(lock_path)
                .map_err(|_| BackendError::ActivityMutationBlocked)?;
            let metadata = lock_file
                .metadata()
                .map_err(|_| BackendError::ActivityStoreStorage)?;
            if !metadata.file_type().is_file()
                || metadata.len() != 0
                || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
            {
                return Err(BackendError::ActivityStoreInvalid);
            }
            lock_file
                .sync_all()
                .map_err(|_| BackendError::ActivityStoreStorage)?;
            parent_directory
                .flush()
                .map_err(|_| BackendError::ActivityStoreStorage)?;
            let temporary = activity_store_temporary_path(activity_store_path)?;
            reconcile_orphan_activity_temporary(&temporary, &parent_directory)?;
            Ok(Self {
                _process_guard: process_guard,
                activity_store_path: activity_store_path.to_path_buf(),
                _lock_file: lock_file,
                _parent_directory: parent_directory,
            })
        }
        #[cfg(not(windows))]
        {
            let parent = activity_store_path
                .parent()
                .ok_or(BackendError::ActivityStoreStorage)?;
            let parent_directory = DurableParentDirectory::open(parent)
                .map_err(|_| BackendError::ActivityStoreStorage)?;
            let temporary = activity_store_temporary_path(activity_store_path)?;
            reconcile_orphan_activity_temporary(&temporary, &parent_directory)?;
            Ok(Self {
                _process_guard: process_guard,
                activity_store_path: activity_store_path.to_path_buf(),
            })
        }
    }
}

/// One freshly validated token response. Public UI strings are created only
/// after every field has passed the strict local policy.
struct ValidatedToken {
    contract: [u8; 20],
    decimals: u8,
    symbol: Option<String>,
    code_hash: [u8; 32],
    balance: TokenAmount,
}

/// Authenticated token store plus the exact bytes observed at mutation start.
/// `baseline.bytes` is `None` only while the sidecar does not yet exist.
struct LoadedTokenStore {
    store: TokenStore,
    baseline: TokenStoreBaseline,
}

/// Compare-and-swap witness captured while the mutation lease is held.
///
/// The bytes prevent a same-generation, different-content writer from being
/// overwritten. The authenticated generation independently proves that one
/// public add/remove operation advances the store exactly once.
struct TokenStoreBaseline {
    bytes: Option<Vec<u8>>,
    generation: u64,
}

/// Serializes the complete token mutation transaction.
///
/// Every process uses the in-process mutex. On Windows (the supported desktop
/// target), the persistent empty sibling lock file is also opened with no share
/// permissions and its handle plus the exact parent-directory handle stay live
/// from baseline load through the final CAS/replace/readback. A crash releases
/// the handle automatically; the empty regular lock file intentionally stays.
///
/// This is a cooperative wallet-process concurrency lease, not a security
/// boundary against another same-user process that deliberately ignores it.
/// AEAD plus exact installed readback makes arbitrary corruption fail closed on
/// this operation or the next open/refresh, but a captured valid old blob can
/// still be rolled back, and an uncooperative compare-to-replace race cannot be
/// excluded without an external ACL/hardware-backed monotonic anchor.
struct TokenMutationLease<'a> {
    _process_guard: MutexGuard<'a, ()>,
    #[cfg(windows)]
    _lock_file: File,
    #[cfg(windows)]
    _parent_directory: DurableParentDirectory,
}

impl<'a> TokenMutationLease<'a> {
    fn acquire(token_store_path: &Path) -> Result<Self, BackendError> {
        let process_guard = TOKEN_STORE_PROCESS_LOCK
            .lock()
            .map_err(|_| BackendError::TokenStoreStorage)?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;

            let parent = token_store_path
                .parent()
                .ok_or(BackendError::TokenStoreStorage)?;
            let parent_directory = DurableParentDirectory::open(parent)
                .map_err(|_| BackendError::TokenStoreStorage)?;
            let lock_path = token_store_lock_path(token_store_path)?;
            let lock_file = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .share_mode(0)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
                .open(lock_path)
                .map_err(|_| BackendError::TokenMutationBlocked)?;
            let metadata = lock_file
                .metadata()
                .map_err(|_| BackendError::TokenStoreStorage)?;
            if !metadata.file_type().is_file()
                || metadata.len() != 0
                || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
            {
                return Err(BackendError::TokenStoreInvalid);
            }
            lock_file
                .sync_all()
                .map_err(|_| BackendError::TokenStoreStorage)?;
            parent_directory
                .flush()
                .map_err(|_| BackendError::TokenStoreStorage)?;
            let temporary = token_store_temporary_path(token_store_path)?;
            reconcile_orphan_token_temporary(&temporary, &parent_directory)?;
            Ok(Self {
                _process_guard: process_guard,
                _lock_file: lock_file,
                _parent_directory: parent_directory,
            })
        }
        #[cfg(not(windows))]
        {
            // Non-Windows builds are test/development conveniences. The
            // process mutex plus exact-byte CAS prevents same-process lost
            // updates and detects cross-process changes before replacement.
            // The supported Windows desktop path additionally holds the
            // no-share sibling lease above for the entire transaction.
            let parent = token_store_path
                .parent()
                .ok_or(BackendError::TokenStoreStorage)?;
            let parent_directory = DurableParentDirectory::open(parent)
                .map_err(|_| BackendError::TokenStoreStorage)?;
            let temporary = token_store_temporary_path(token_store_path)?;
            reconcile_orphan_token_temporary(&temporary, &parent_directory)?;
            Ok(Self {
                _process_guard: process_guard,
            })
        }
    }
}

/// Holds both authenticated-sidecar namespaces while a brand-new v2 vault is
/// installed. Every dual acquisition is token first, then activity, which is
/// the single global order and prevents cooperating wallet processes from
/// creating a stale sidecar between the final absence bookend and activation.
struct NewV2SidecarNamespaceLease<'a> {
    _namespace_parent: DurableParentDirectory,
    _token_lease: TokenMutationLease<'a>,
    _activity_lease: ActivityMutationLease<'a>,
    token_store_path: PathBuf,
    activity_store_path: PathBuf,
}

impl<'a> NewV2SidecarNamespaceLease<'a> {
    fn acquire(token_store_path: &Path, activity_store_path: &Path) -> Result<Self, BackendError> {
        let token_parent = token_store_path
            .parent()
            .ok_or(BackendError::TokenStoreStorage)?;
        let activity_parent = activity_store_path
            .parent()
            .ok_or(BackendError::ActivityStoreStorage)?;
        if token_parent != activity_parent {
            return Err(BackendError::StorageUnavailable);
        }
        // A first-run wallet may lack both fixed application-directory levels.
        // Create at most those two components from the deepest existing exact
        // ancestor and flush each containing-directory entry; retain the final
        // non-reparse parent through the global token-to-activity lease order
        // and vault activation.
        let namespace_parent = open_or_create_durable_namespace_parent(token_parent)?;
        let token_lease = TokenMutationLease::acquire(token_store_path)?;
        let activity_lease = ActivityMutationLease::acquire(activity_store_path)?;
        let lease = Self {
            _namespace_parent: namespace_parent,
            _token_lease: token_lease,
            _activity_lease: activity_lease,
            token_store_path: token_store_path.to_path_buf(),
            activity_store_path: activity_store_path.to_path_buf(),
        };
        lease.verify_absent()?;
        Ok(lease)
    }

    fn verify_absent(&self) -> Result<(), BackendError> {
        if read_token_store_file(&self.token_store_path)?.is_some() {
            return Err(BackendError::TokenStoreChanged);
        }
        if read_activity_store_file(&self.activity_store_path)?.is_some() {
            return Err(BackendError::ActivityStoreChanged);
        }
        Ok(())
    }
}

fn open_or_create_durable_namespace_parent(
    parent: &Path,
) -> Result<DurableParentDirectory, BackendError> {
    let application_root = parent.parent().ok_or(BackendError::StorageUnavailable)?;
    let trusted_base = application_root
        .parent()
        .ok_or(BackendError::StorageUnavailable)?;
    let mut current_directory = DurableParentDirectory::open(trusted_base)?;

    // Production has the two fixed components `YourWallet/SepoliaDemo` below
    // an already-existing platform data directory. Re-open and flush both
    // entries on every attempt, including when a previous process crashed
    // after mkdir but before its containing-directory flush completed.
    for component in [application_root, parent] {
        match fs::create_dir(component) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(BackendError::StorageUnavailable),
        }
        let created = DurableParentDirectory::open(component)?;
        created.flush()?;
        current_directory.flush()?;
        current_directory = created;
    }
    Ok(current_directory)
}

trait MonotonicClock: Send {
    fn now(&self) -> Instant;
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SendRawError {
    SessionRevoked,
    BroadcastUnknown,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ActivityRpcBlock {
    number: u64,
    hash: [u8; 32],
}

#[derive(Clone)]
struct ActivityRpcTransaction {
    hash: [u8; 32],
    from: [u8; 20],
    to: [u8; 20],
    nonce: Word,
    value: Word,
    input: Vec<u8>,
    gas_limit: Word,
    priority_fee: Word,
    maximum_fee: Word,
    y_parity: u8,
    r: Word,
    s: Word,
    block: Option<ActivityRpcBlock>,
    transaction_index: Option<u64>,
}

#[derive(Clone, Copy)]
struct ActivityRpcReceipt {
    transaction_hash: [u8; 32],
    from: [u8; 20],
    to: [u8; 20],
    outcome: InclusionOutcome,
    block: ActivityRpcBlock,
    transaction_index: u64,
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
    fn latest_nonce(&self, address: [u8; 20]) -> Result<Word, ()> {
        #[cfg(test)]
        {
            self.pending_nonce(address)
        }
        #[cfg(not(test))]
        {
            let _ = address;
            Err(())
        }
    }
    fn activity_transaction(
        &self,
        transaction_hash: [u8; 32],
    ) -> Result<Option<ActivityRpcTransaction>, ()> {
        #[cfg(test)]
        {
            let _ = transaction_hash;
            Ok(None)
        }
        #[cfg(not(test))]
        {
            let _ = transaction_hash;
            Err(())
        }
    }
    fn activity_receipt(
        &self,
        transaction_hash: [u8; 32],
    ) -> Result<Option<ActivityRpcReceipt>, ()> {
        #[cfg(test)]
        {
            let _ = transaction_hash;
            Ok(None)
        }
        #[cfg(not(test))]
        {
            let _ = transaction_hash;
            Err(())
        }
    }
    fn activity_block(&self, number: u64) -> Result<Option<ActivityRpcBlock>, ()> {
        #[cfg(test)]
        {
            let _ = number;
            Ok(None)
        }
        #[cfg(not(test))]
        {
            let _ = number;
            Err(())
        }
    }
    fn activity_head(&self) -> Result<ActivityRpcBlock, ()> {
        #[cfg(test)]
        {
            Ok(ActivityRpcBlock {
                number: 1,
                hash: [0xa5; 32],
            })
        }
        #[cfg(not(test))]
        {
            Err(())
        }
    }
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
    fn send_raw_transaction(
        &self,
        signed: &[u8],
        permit: &SessionPermit<'_>,
    ) -> Result<[u8; 32], SendRawError>;
    fn contract_code(&self, contract: [u8; 20]) -> Result<Vec<u8>, ()> {
        let _ = contract;
        Err(())
    }
    fn erc20_decimals(&self, contract: [u8; 20]) -> Result<Vec<u8>, ()> {
        let _ = contract;
        Err(())
    }
    fn erc20_symbol(&self, contract: [u8; 20]) -> Result<Vec<u8>, ()> {
        let _ = contract;
        Err(())
    }
    fn erc20_balance_of(&self, contract: [u8; 20], owner: [u8; 20]) -> Result<Vec<u8>, ()> {
        let _ = (contract, owner);
        Err(())
    }
    #[allow(clippy::too_many_arguments)]
    fn erc20_transfer_preflight(
        &self,
        sender: [u8; 20],
        contract: [u8; 20],
        recipient: [u8; 20],
        amount: TokenAmount,
        nonce: Word,
        gas_limit: Word,
        priority_fee: Word,
        maximum_fee: Word,
    ) -> Result<Vec<u8>, ()> {
        let _ = (
            sender,
            contract,
            recipient,
            amount,
            nonce,
            gas_limit,
            priority_fee,
            maximum_fee,
        );
        Err(())
    }
    #[allow(clippy::too_many_arguments)]
    fn estimate_erc20_transfer_gas(
        &self,
        sender: [u8; 20],
        contract: [u8; 20],
        recipient: [u8; 20],
        amount: TokenAmount,
        nonce: Word,
        priority_fee: Word,
        maximum_fee: Word,
    ) -> Result<Word, ()> {
        let _ = (
            sender,
            contract,
            recipient,
            amount,
            nonce,
            priority_fee,
            maximum_fee,
        );
        Err(())
    }
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
        let token_store_path = sibling_token_store_path(&vault_v2_path)?;
        let activity_store_path = sibling_activity_store_path(&vault_v2_path)?;
        let rpc = rpc::SepoliaRpc::new();
        Ok(Self {
            vault_path,
            vault_v2_path,
            pending_path,
            token_store_path,
            activity_store_path,
            rpc: Box::new(LiveRpc(rpc)),
            unlocked: None,
            selected_account_index: 0,
            pending_generation: None,
            last_balance: None,
            prepared: None,
            prepared_pending_retry: None,
            clock: Box::new(SystemClock),
            #[cfg(test)]
            sign_attempts: 0,
            #[cfg(test)]
            fail_activity_persist_for_test: false,
        })
    }

    #[cfg(test)]
    fn with_rpc(vault_path: PathBuf, rpc: impl RpcAccess + 'static) -> Self {
        let pending_path = vault_path.with_file_name("pending-v1.bin");
        let vault_v2_path = vault_path.with_file_name("vault-v2.bin");
        let token_store_path = vault_path.with_file_name("tokens-v1.bin");
        let activity_store_path = vault_path.with_file_name("activity-v1.bin");
        Self {
            vault_path,
            vault_v2_path,
            pending_path,
            token_store_path,
            activity_store_path,
            rpc: Box::new(rpc),
            unlocked: None,
            selected_account_index: 0,
            pending_generation: None,
            last_balance: None,
            prepared: None,
            prepared_pending_retry: None,
            clock: Box::new(SystemClock),
            sign_attempts: 0,
            fail_activity_persist_for_test: false,
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

    /// Immediately forgets every in-memory session capability.
    ///
    /// The signed pending-broadcast file is intentionally preserved: it is an
    /// already-authorized transaction recovery record, not an unlocked key or
    /// a mutable transfer preview.
    pub fn lock(&mut self) {
        drop(self.unlocked.take());
        self.selected_account_index = 0;
        drop(self.pending_generation.take());
        self.prepared = None;
        self.prepared_pending_retry = None;
        self.last_balance = None;
    }

    /// Returns the current public address, if the vault is unlocked.
    #[must_use]
    #[cfg(test)]
    pub fn address(&self) -> Option<String> {
        self.unlocked
            .as_ref()
            .and_then(|wallet| wallet.account_address(self.selected_account_index).ok())
            .map(checksum_address)
    }

    /// Retries exactly the previously persisted signed transaction bytes.
    ///
    /// This never creates a new signature or nonce. The pending record remains
    /// on every error or hash mismatch and is deleted only after an exact hash
    /// match from the pinned Sepolia endpoint.
    pub fn retry_pending(&mut self, permit: &SessionPermit<'_>) -> Result<SendReceipt, String> {
        self.retry_pending_with_permit(permit).map_err(error_text)
    }

    /// Strictly recover and attribute a durable type-2 sender, then freeze the
    /// exact bytes for the UI's separate hold-to-retry confirmation.
    pub fn inspect_pending_broadcast(
        &mut self,
        permit: &SessionPermit<'_>,
    ) -> Result<PendingBroadcastPreview, String> {
        self.prepare_pending_retry(Some(permit)).map_err(error_text)
    }

    fn snapshot(&self) -> Result<WalletSnapshot, BackendError> {
        let wallet = self.unlocked.as_ref().ok_or(BackendError::Locked)?;
        let (_, wallet_kind, _) = wallet.validated_metadata()?;
        let address = wallet.account_address(self.selected_account_index)?;
        let accounts = wallet.account_snapshots()?;
        let balance_eth = self
            .last_balance
            .as_ref()
            .filter(|balance| {
                balance.account_index == self.selected_account_index && balance.address == address
            })
            .map_or_else(
                || "조회 전".to_owned(),
                |balance| format_ether(balance.value),
            );
        let activity = self.activity_snapshots(self.selected_account_index)?;
        Ok(WalletSnapshot {
            accounts,
            selected_account_index: self.selected_account_index,
            balance_eth,
            wallet_kind,
            pending_broadcast: self
                .prepared_pending_retry
                .as_ref()
                .map(PreparedPendingRetry::preview),
            activity,
        })
    }

    fn snapshot_or_lock(&mut self) -> Result<WalletSnapshot, BackendError> {
        let snapshot = self.snapshot();
        if snapshot.is_err() {
            // An authenticated sidecar is part of the unlocked public state.
            // Never report an activation/refresh failure while retaining keys
            // in a backend that the caller reasonably believes stayed locked.
            self.lock();
        }
        snapshot
    }

    fn selected_account(&self) -> Result<(u8, [u8; 20]), BackendError> {
        let wallet = self.unlocked.as_ref().ok_or(BackendError::Locked)?;
        let address = wallet.account_address(self.selected_account_index)?;
        Ok((self.selected_account_index, address))
    }

    fn select_account_inner(&mut self, index: u8) -> Result<WalletSnapshot, BackendError> {
        let wallet = self.unlocked.as_ref().ok_or(BackendError::Locked)?;
        wallet.account_address(index)?;
        if index == self.selected_account_index {
            return self.snapshot_or_lock();
        }
        if self.pending_broadcast_exists() {
            return Err(BackendError::PendingExists);
        }
        if self.prepared.is_some() {
            return Err(BackendError::AccountSwitchBlocked);
        }
        if self.pending_generation.is_some() {
            return Err(BackendError::GenerationPending);
        }
        self.selected_account_index = index;
        self.last_balance = None;
        self.snapshot_or_lock()
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
        self.selected_account_index = 0;
        self.last_balance = Some(AccountBalance {
            account_index: 0,
            address,
            value: Word::ZERO,
        });
        self.snapshot_or_lock()
    }

    fn open(&mut self, password: &str) -> Result<WalletSnapshot, BackendError> {
        self.prepared = None;
        self.prepared_pending_retry = None;
        self.pending_generation = None;
        self.unlocked = None;
        self.selected_account_index = 0;
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
        if self.pending_broadcast_exists()
            && let Err(error) = self.prepare_pending_retry(None)
        {
            self.unlocked = None;
            self.prepared_pending_retry = None;
            return Err(error);
        }
        self.snapshot_or_lock()
    }

    fn begin_generate(
        &mut self,
        words: NewMnemonicWords,
        password: SensitiveText,
        password_confirmation: SensitiveText,
    ) -> Result<GeneratedBackupReveal, BackendError> {
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
        let (first_address, kind, _) = validated_wallet_metadata(&wallet)?;
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
            stage: PendingGeneratedStage::Display,
        });
        generated_backup_reveal(export, first_address, expires_at)
    }

    fn begin_generated_challenge(&mut self) -> Result<GeneratedBackupChallenge, BackendError> {
        self.prepared = None;
        let mut pending = self
            .pending_generation
            .take()
            .ok_or(BackendError::NoPendingGeneration)?;
        if self.clock.now() >= pending.expires_at {
            return Err(BackendError::GenerationExpired);
        }
        if !matches!(pending.stage, PendingGeneratedStage::Display) {
            return Err(BackendError::BackupConfirmationFailed);
        }
        let word_count = pending
            .wallet
            .word_count()
            .filter(|count| matches!(count, 12 | 24))
            .ok_or(BackendError::WalletMetadataInvalid)?;
        let positions = random_backup_challenge_positions(word_count)?;
        pending.stage = PendingGeneratedStage::Challenge { positions };
        let challenge = GeneratedBackupChallenge::new(positions, pending.expires_at);
        self.pending_generation = Some(pending);
        Ok(challenge)
    }

    fn confirm_generated(
        &mut self,
        confirmation: GeneratedBackupConfirmation,
        permit: &SessionPermit<'_>,
    ) -> Result<WalletSnapshot, BackendError> {
        self.prepared = None;
        let pending = self
            .pending_generation
            .take()
            .ok_or(BackendError::NoPendingGeneration)?;
        let PendingGeneratedStage::Challenge { positions } = pending.stage else {
            return Err(BackendError::BackupConfirmationFailed);
        };

        self.ensure_management_mutation_allowed()?;
        let metadata = confirmed_metadata(VaultOrigin::GeneratedMnemonic)?;
        // First authority boundary: do not even compare the submitted backup
        // data after the originating session has been revoked or expired.
        self.ensure_generated_confirmation_live(permit, pending.expires_at)?;
        let (words, first_address) = confirmation.into_zeroizing_parts();
        pending
            .wallet
            .verify_generated_backup(positions, &words, &first_address)
            .map_err(map_secret_error)?;
        drop(words);
        drop(first_address);

        // Second boundary: successful verification grants no authority after
        // this point unless the session and original deadline remain live.
        self.ensure_generated_confirmation_live(permit, pending.expires_at)?;
        let sealed =
            seal_vault_v2(&pending.wallet, &pending.password, metadata).map_err(map_vault_error)?;
        // Third boundary: sealing performs the first expensive KDF. Recheck
        // before authenticated open performs the second.
        self.ensure_generated_confirmation_live(permit, pending.expires_at)?;
        let opened =
            open_vault_v2(sealed.as_bytes(), &pending.password).map_err(map_vault_error)?;
        let original_metadata = validated_wallet_metadata(&pending.wallet)?;
        if validated_wallet_metadata(opened.wallet())? != original_metadata {
            return Err(BackendError::WalletMetadataInvalid);
        }
        // Fourth boundary: never activate a stale seal/open/validation result.
        self.ensure_generated_confirmation_live(permit, pending.expires_at)?;
        self.ensure_management_mutation_allowed()?;
        let sidecar_namespace_lease =
            NewV2SidecarNamespaceLease::acquire(&self.token_store_path, &self.activity_store_path)?;
        // Fifth boundary immediately adjacent to the only filesystem write,
        // after acquiring the ordered token→activity namespace witnesses.
        self.ensure_generated_confirmation_live(permit, pending.expires_at)?;
        write_new_file(&self.vault_v2_path, sealed.as_bytes())?;
        sidecar_namespace_lease.verify_absent()?;

        self.unlocked = Some(UnlockedWallet::V2(opened));
        self.selected_account_index = 0;
        self.last_balance = Some(AccountBalance {
            account_index: 0,
            address: original_metadata.0,
            value: Word::ZERO,
        });
        let snapshot = self.snapshot_or_lock();
        drop(sidecar_namespace_lease);
        snapshot
    }

    fn ensure_generated_confirmation_live(
        &self,
        permit: &SessionPermit<'_>,
        expires_at: Instant,
    ) -> Result<(), BackendError> {
        ensure_session_current(permit)?;
        if self.clock.now() >= expires_at {
            Err(BackendError::GenerationExpired)
        } else {
            Ok(())
        }
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
        self.prepared_pending_retry = None;
        if self.pending_generation.is_some() {
            return Err(BackendError::GenerationPending);
        }
        if path_may_exist(&self.vault_v2_path) {
            return Err(BackendError::AlreadyExists);
        }
        let sidecar_namespace_lease =
            NewV2SidecarNamespaceLease::acquire(&self.token_store_path, &self.activity_store_path)?;
        if !path_may_exist(&self.vault_path) {
            return Err(BackendError::LegacyNotFound);
        }

        // A v1 wallet may already have one signed native transaction from an
        // older build. Pin that exact object for the whole migration instead
        // of either broadcasting or deleting it. The signature is attributed
        // only after the authenticated legacy key yields account 0 below.
        let pending_for_migration = match fs::symlink_metadata(&self.pending_path) {
            Ok(_) => {
                let mut lease = PendingFileLease::open(&self.pending_path)?;
                let record = lease.read_record()?;
                Some((lease, record))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(BackendError::PendingInvalid),
        };

        let old_password = take_sensitive_zeroizing(old_password);
        validate_password(old_password.as_str())?;
        let mut legacy_lease = LegacyVaultMigrationLease::open(&self.vault_path)?;
        let legacy_bytes = legacy_lease.read_exact()?;
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
        let mut prepared_pending_retry = match pending_for_migration {
            Some((mut lease, record)) => {
                let recovered = recover_signed_type_two_sender(record.raw_transaction.as_slice())?;
                if recovered != legacy_address {
                    return Err(BackendError::PendingAccountMismatch);
                }
                let decoded = decode_pending_activity(record.raw_transaction.as_slice())?;
                if !matches!(decoded.transfer, DecodedPendingTransfer::Native { .. }) {
                    // Legacy v1 never had an authenticated saved-token sidecar,
                    // so an ERC-20 record cannot be bound soundly during this
                    // migration.
                    return Err(BackendError::PendingInvalid);
                }
                verify_pending_lease(
                    &mut lease,
                    record.transaction_hash,
                    record.raw_transaction.as_slice(),
                )?;
                Some(PreparedPendingRetry {
                    sender_account_index: 0,
                    sender: legacy_address,
                    transaction_hash: record.transaction_hash,
                    raw_transaction: record.raw_transaction,
                    lease,
                })
            }
            None => None,
        };
        let new_password = matching_vault_password(new_password, new_password_confirmation)?;
        let metadata = confirmed_metadata(VaultOrigin::MigratedV1RawPrivateKey)?;
        let sealed = seal_vault_v2(&wallet, &new_password, metadata).map_err(map_vault_error)?;
        let opened = open_vault_v2(sealed.as_bytes(), &new_password).map_err(map_vault_error)?;
        let (opened_address, _, _) = validated_wallet_metadata(opened.wallet())?;
        if opened_address != legacy_address {
            return Err(BackendError::WalletMetadataInvalid);
        }
        if let Some(prepared) = prepared_pending_retry.as_mut() {
            verify_pending_lease(
                &mut prepared.lease,
                prepared.transaction_hash,
                prepared.raw_transaction.as_slice(),
            )?;
        } else if self.pending_broadcast_exists() {
            // The name was absent when migration began. A newly appearing
            // pending object belongs to another operation and blocks the vault
            // transition rather than being silently adopted.
            return Err(BackendError::PendingChanged);
        }
        if path_may_exist(&self.vault_v2_path) {
            return Err(BackendError::AlreadyExists);
        }
        let legacy_readback = legacy_lease.read_exact()?;
        if legacy_readback.as_slice() != legacy_bytes.as_slice() {
            return Err(BackendError::WalletChanged);
        }
        let mut persisted_v2_lease =
            CreatedV2VaultMigrationLease::create(&self.vault_v2_path, sealed.as_bytes())?;
        let persisted_v2 = match persisted_v2_lease.read_exact() {
            Ok(bytes) => bytes,
            Err(error) => {
                persisted_v2_lease.abort()?;
                return Err(error);
            }
        };
        if persisted_v2.as_slice() != sealed.as_bytes() {
            persisted_v2_lease.abort()?;
            self.unlocked = None;
            self.last_balance = None;
            return Err(BackendError::WalletChanged);
        }
        let opened = match open_vault_v2(persisted_v2.as_slice(), &new_password) {
            Ok(opened) => opened,
            Err(error) => {
                persisted_v2_lease.abort()?;
                return Err(map_vault_error(error));
            }
        };
        let (opened_address, _, _) = match validated_wallet_metadata(opened.wallet()) {
            Ok(metadata) => metadata,
            Err(error) => {
                persisted_v2_lease.abort()?;
                return Err(error);
            }
        };
        if opened_address != legacy_address {
            persisted_v2_lease.abort()?;
            self.unlocked = None;
            self.last_balance = None;
            return Err(BackendError::WalletChanged);
        }
        if let Some(prepared) = prepared_pending_retry.as_mut() {
            verify_pending_lease(
                &mut prepared.lease,
                prepared.transaction_hash,
                prepared.raw_transaction.as_slice(),
            )?;
        } else if self.pending_broadcast_exists() {
            self.unlocked = None;
            self.last_balance = None;
            return Err(BackendError::PendingChanged);
        }
        let legacy_readback = legacy_lease.read_exact()?;
        if legacy_readback.as_slice() != legacy_bytes.as_slice() {
            self.unlocked = None;
            self.last_balance = None;
            return Err(BackendError::WalletChanged);
        }
        if persisted_v2_lease.verify_exact(sealed.as_bytes()).is_err() {
            self.unlocked = None;
            self.last_balance = None;
            return Err(BackendError::WalletChanged);
        }
        sidecar_namespace_lease.verify_absent()?;
        persisted_v2_lease.install_exact(&self.vault_v2_path)?;
        persisted_v2_lease.verify_exact(sealed.as_bytes())?;
        // Recheck the pending object at the last reversible boundary. An old
        // v1 process may create or replace the name while the authenticated v2
        // object is being installed. Any such change aborts that still-
        // uncommitted v2 object and leaves the exact legacy vault intact.
        if let Some(prepared) = prepared_pending_retry.as_mut() {
            verify_pending_lease(
                &mut prepared.lease,
                prepared.transaction_hash,
                prepared.raw_transaction.as_slice(),
            )?;
        } else if self.pending_broadcast_exists() {
            self.unlocked = None;
            self.last_balance = None;
            return Err(BackendError::PendingChanged);
        }
        // Every pending/v1/v2 bookend and the exact-handle same-directory
        // install have passed. From this point a reported legacy-delete/flush
        // failure is commit-uncertain and must retain the exact authenticated
        // v2 file; before this point Drop removes only the migrating temp.
        persisted_v2_lease.mark_committed()?;
        if legacy_lease.delete_exact(&self.vault_path).is_err() {
            self.unlocked = None;
            self.last_balance = None;
            return Err(BackendError::MigrationCleanup);
        }
        self.unlocked = Some(UnlockedWallet::V2(opened));
        self.selected_account_index = 0;
        self.last_balance = None;
        self.prepared_pending_retry = prepared_pending_retry;
        let snapshot = self.snapshot_or_lock();
        // Both migration leases stay in scope through activation/snapshot.
        // The v2 no-share handle therefore pins the exact authenticated file
        // while the exact v1 handle is deleted and the in-memory wallet is
        // activated. The legacy lease retains the parent directory and the
        // non-Windows process-local guard until this point as well.
        drop(persisted_v2_lease);
        drop(legacy_lease);
        snapshot
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
        let (selected_index, selected_address) = self.selected_account()?;
        let export = match self.unlocked.as_ref().ok_or(BackendError::Locked)? {
            UnlockedWallet::V2(_) => {
                let opened = self.reopen_authenticated_v2(password)?;
                let reopened_account = opened
                    .wallet()
                    .account(usize::from(selected_index))
                    .ok_or(BackendError::UnsupportedAccount)?;
                let expected_index = u32::from(selected_index);
                if reopened_account.requested_index() != expected_index
                    || reopened_account.actual_index() != expected_index
                    || reopened_account.address().as_bytes() != &selected_address
                {
                    return Err(BackendError::WalletChanged);
                }
                opened
                    .wallet()
                    .export_account_private_key(u32::from(selected_index))
                    .map_err(map_secret_error)?
            }
            UnlockedWallet::LegacyV1 {
                private_key,
                address,
            } => {
                if selected_index != 0 || selected_address != *address {
                    return Err(BackendError::UnsupportedAccount);
                }
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
        account_private_key_reveal(export, selected_index, selected_address)
    }

    fn persist_new_v2(
        &mut self,
        wallet: WalletSecret,
        password: VaultPassword,
        origin: VaultOrigin,
    ) -> Result<WalletSnapshot, BackendError> {
        self.ensure_management_mutation_allowed()?;
        let (account_zero, _, _) = validated_wallet_metadata(&wallet)?;
        let metadata = confirmed_metadata(origin)?;
        let sealed = seal_vault_v2(&wallet, &password, metadata).map_err(map_vault_error)?;
        let opened = open_vault_v2(sealed.as_bytes(), &password).map_err(map_vault_error)?;
        validated_wallet_metadata(opened.wallet())?;
        self.ensure_management_mutation_allowed()?;
        let sidecar_namespace_lease =
            NewV2SidecarNamespaceLease::acquire(&self.token_store_path, &self.activity_store_path)?;
        write_new_file(&self.vault_v2_path, sealed.as_bytes())?;
        sidecar_namespace_lease.verify_absent()?;
        self.unlocked = Some(UnlockedWallet::V2(opened));
        self.selected_account_index = 0;
        self.last_balance = Some(AccountBalance {
            account_index: 0,
            address: account_zero,
            value: Word::ZERO,
        });
        let snapshot = self.snapshot_or_lock();
        drop(sidecar_namespace_lease);
        snapshot
    }

    fn ensure_management_mutation_allowed(&self) -> Result<(), BackendError> {
        if self.pending_broadcast_exists() {
            return Err(BackendError::PendingExists);
        }
        if path_may_exist(&self.activity_store_path) {
            return Err(BackendError::ActivityStoreChanged);
        }
        if path_may_exist(&self.token_store_path) {
            return Err(BackendError::TokenStoreChanged);
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
        let (account_index, address) = self.selected_account()?;
        self.rpc
            .verify_sepolia()
            .map_err(|()| BackendError::RpcUnavailable)?;
        let balance = self
            .rpc
            .balance(address)
            .map_err(|()| BackendError::BalanceUnavailable)?;
        self.last_balance = Some(AccountBalance {
            account_index,
            address,
            value: balance,
        });
        self.snapshot_or_lock()
    }

    fn refresh_activity_inner(
        &mut self,
        transaction_hash: &str,
        permit: &SessionPermit<'_>,
    ) -> Result<TransactionActivitySnapshot, BackendError> {
        ensure_session_current(permit)?;
        let hash = parse_transaction_hash(transaction_hash)?;
        let activity_context = self.activity_context()?;
        let activity_lease = ActivityMutationLease::acquire(&self.activity_store_path)?;
        let mut loaded = self.load_activity_store(&activity_context)?;
        let entry = loaded
            .store
            .find(&hash)
            .ok_or(BackendError::ActivityIdentityMismatch)?;
        if entry.identity().account_index() != self.selected_account_index
            || self
                .unlocked
                .as_ref()
                .ok_or(BackendError::Locked)?
                .account_address(self.selected_account_index)?
                != *entry.identity().sender()
        {
            return Err(BackendError::ActivityIdentityMismatch);
        }
        let (next_status, next_observations) = self.observe_activity(entry, permit)?;
        ensure_session_current(permit)?;
        let mutation = loaded
            .store
            .transition(&hash, next_status, next_observations)
            .map_err(map_activity_store_error)?;
        if mutation == ActivityMutation::Changed {
            self.persist_activity_store(
                &activity_lease,
                &activity_context,
                &loaded.store,
                &loaded.baseline,
                &hash,
            )?;
        }
        let readback = loaded
            .store
            .find(&hash)
            .ok_or(BackendError::ActivityIdentityMismatch)?;
        activity_snapshot_from_entry(readback)
    }

    fn observe_activity(
        &self,
        entry: &ActivityEntry,
        permit: &SessionPermit<'_>,
    ) -> Result<(ActivityStatus, ObservationCounters), BackendError> {
        ensure_session_current(permit)?;
        self.rpc
            .verify_sepolia()
            .map_err(|()| BackendError::RpcUnavailable)?;
        ensure_session_current(permit)?;
        let head_before = self
            .rpc
            .activity_head()
            .map_err(|()| BackendError::RpcUnavailable)?;
        ensure_session_current(permit)?;
        let transaction = self
            .rpc
            .activity_transaction(*entry.identity().transaction_hash())
            .map_err(|()| BackendError::RpcUnavailable)?;
        if let Some(transaction) = transaction.as_ref() {
            canonical_observed_type_two_bytes(transaction)?;
        }
        ensure_session_current(permit)?;
        let receipt = self
            .rpc
            .activity_receipt(*entry.identity().transaction_hash())
            .map_err(|()| BackendError::RpcUnavailable)?;
        ensure_session_current(permit)?;
        let latest_nonce = self
            .rpc
            .latest_nonce(*entry.identity().sender())
            .map_err(|()| BackendError::RpcUnavailable)?;
        ensure_session_current(permit)?;
        let former_inclusion = match entry.status() {
            ActivityStatus::Included(inclusion) | ActivityStatus::Reorged(inclusion) => {
                Some(inclusion)
            }
            ActivityStatus::Submitted
            | ActivityStatus::Pending
            | ActivityStatus::DroppedCandidate
            | ActivityStatus::ReplacementSuspected => None,
        };
        let receipt_block = match receipt.as_ref() {
            Some(receipt) => self
                .rpc
                .activity_block(receipt.block.number)
                .map_err(|()| BackendError::RpcUnavailable)?,
            None => None,
        };
        ensure_session_current(permit)?;
        let former_block = match former_inclusion {
            Some(former)
                if receipt
                    .as_ref()
                    .is_some_and(|receipt| receipt.block.number == former.block_number()) =>
            {
                receipt_block
            }
            Some(former) => self
                .rpc
                .activity_block(former.block_number())
                .map_err(|()| BackendError::RpcUnavailable)?,
            None => None,
        };
        ensure_session_current(permit)?;
        let head_after = self
            .rpc
            .activity_head()
            .map_err(|()| BackendError::RpcUnavailable)?;
        ensure_session_current(permit)?;
        if head_before != head_after || head_before.number == 0 || head_before.hash == [0; 32] {
            return Err(BackendError::ActivityObservationInvalid);
        }
        if let Some(transaction) = transaction.as_ref()
            && !activity_transaction_matches_identity(transaction, entry.identity())
        {
            return Err(BackendError::ActivityIdentityMismatch);
        }
        let former_reorg_proven = match former_inclusion {
            Some(former) if head_before.number < former.block_number() => {
                // A shorter, stable head with no header is evidence that the
                // old anchor is not currently reachable, but observation
                // counters intentionally reject decreasing head numbers. Do
                // not fabricate a monotone head or mutate on this ambiguous
                // rollback; a later stable head can provide canonical proof.
                return Err(BackendError::ActivityObservationInvalid);
            }
            Some(former) => match former_block {
                Some(block) if block.number == former.block_number() => {
                    block.hash != *former.block_hash()
                }
                Some(_) => return Err(BackendError::ActivityObservationInvalid),
                None => false,
            },
            None => false,
        };
        if let Some(receipt) = receipt {
            let transaction = transaction
                .as_ref()
                .ok_or(BackendError::ActivityObservationInvalid)?;
            if !activity_receipt_matches_identity(&receipt, entry.identity())
                || transaction.block != Some(receipt.block)
                || transaction.transaction_index != Some(receipt.transaction_index)
            {
                return Err(BackendError::ActivityIdentityMismatch);
            }
            let Some(canonical) = receipt_block else {
                if former_reorg_proven {
                    let former =
                        former_inclusion.ok_or(BackendError::ActivityObservationInvalid)?;
                    let observations = entry
                        .observations()
                        .record_missing(head_before.number)
                        .map_err(map_activity_store_error)?;
                    return Ok((ActivityStatus::Reorged(former), observations));
                }
                return Err(BackendError::ActivityObservationInvalid);
            };
            if canonical != receipt.block || canonical.number > head_before.number {
                if former_reorg_proven {
                    let former =
                        former_inclusion.ok_or(BackendError::ActivityObservationInvalid)?;
                    let observations = entry
                        .observations()
                        .record_missing(head_before.number)
                        .map_err(map_activity_store_error)?;
                    return Ok((ActivityStatus::Reorged(former), observations));
                }
                return Err(BackendError::ActivityObservationInvalid);
            }
            let inclusion = Inclusion::new(
                receipt.outcome,
                canonical.number,
                canonical.hash,
                head_before.number,
                head_before.hash,
            )
            .map_err(map_activity_store_error)?;
            if let Some(former) = former_inclusion
                && (former.block_number() != inclusion.block_number()
                    || former.block_hash() != inclusion.block_hash())
            {
                if !former_reorg_proven {
                    // Two distinct anchors cannot both canonically contain the
                    // same transaction. Preserve the prior row until the old
                    // anchor is independently proven non-canonical.
                    return Err(BackendError::ActivityObservationInvalid);
                }
                if entry.status() == ActivityStatus::Included(former) {
                    let observations = entry
                        .observations()
                        .record_missing(head_before.number)
                        .map_err(map_activity_store_error)?;
                    return Ok((ActivityStatus::Reorged(former), observations));
                }
            }
            if let Some(former) = former_inclusion
                && former.block_number() == inclusion.block_number()
                && former.block_hash() == inclusion.block_hash()
                && former.outcome() != inclusion.outcome()
            {
                // The receipt outcome is committed by the transaction trie at
                // this exact anchor; changing it without an anchor change is a
                // contradictory observation, not a reorg signal.
                return Err(BackendError::ActivityObservationInvalid);
            }
            let observations = entry
                .observations()
                .record_present(head_before.number)
                .map_err(map_activity_store_error)?;
            return Ok((ActivityStatus::Included(inclusion), observations));
        }

        if matches!(entry.status(), ActivityStatus::Reorged(_))
            && let Some(transaction) = transaction.as_ref()
        {
            if transaction.block.is_some() || !former_reorg_proven {
                return Err(BackendError::ActivityObservationInvalid);
            }
            let observations = entry
                .observations()
                .record_present(head_before.number)
                .map_err(map_activity_store_error)?;
            return Ok((ActivityStatus::Pending, observations));
        }
        if let Some(former) = former_inclusion {
            if !former_reorg_proven {
                // A null receipt alone cannot demote a still-canonical
                // inclusion. Preserve the durable row and generation.
                return Err(BackendError::ActivityObservationInvalid);
            }
            let observations = entry
                .observations()
                .record_missing(head_before.number)
                .map_err(map_activity_store_error)?;
            return Ok((ActivityStatus::Reorged(former), observations));
        }
        if transaction.is_some() {
            let observations = entry
                .observations()
                .record_present(head_before.number)
                .map_err(map_activity_store_error)?;
            return Ok((ActivityStatus::Pending, observations));
        }
        let observations = entry
            .observations()
            .record_missing(head_before.number)
            .map_err(map_activity_store_error)?;
        let status = if latest_nonce > Word::from_be_bytes(*entry.identity().nonce()) {
            ActivityStatus::ReplacementSuspected
        } else if observations.dropped_candidate_ready() {
            ActivityStatus::DroppedCandidate
        } else {
            entry.status()
        };
        Ok((status, observations))
    }

    /// Checks the node before retrying a frozen transaction. A stable,
    /// strictly matching observation proves that a previous broadcast already
    /// reached the node, so the caller must commit history and clean the exact
    /// pending object without broadcasting again. Only a stable `None` allows
    /// one retry broadcast.
    fn pending_transaction_is_observed(
        &self,
        identity: &TransactionIdentity,
        expected_raw: &[u8],
        permit: &SessionPermit<'_>,
    ) -> Result<bool, BackendError> {
        ensure_session_current(permit)?;
        self.rpc
            .verify_sepolia()
            .map_err(|()| BackendError::RpcUnavailable)?;
        ensure_session_current(permit)?;
        let head_before = self
            .rpc
            .activity_head()
            .map_err(|()| BackendError::RpcUnavailable)?;
        ensure_session_current(permit)?;
        let transaction = self
            .rpc
            .activity_transaction(*identity.transaction_hash())
            .map_err(|()| BackendError::RpcUnavailable)?;
        ensure_session_current(permit)?;
        let head_after = self
            .rpc
            .activity_head()
            .map_err(|()| BackendError::RpcUnavailable)?;
        ensure_session_current(permit)?;
        if head_before != head_after || head_before.number == 0 || head_before.hash == [0; 32] {
            return Err(BackendError::ActivityObservationInvalid);
        }
        match transaction {
            Some(transaction) if activity_transaction_matches_identity(&transaction, identity) => {
                let canonical = canonical_observed_type_two_bytes(&transaction)?;
                if canonical.as_slice() != expected_raw {
                    return Err(BackendError::ActivityIdentityMismatch);
                }
                Ok(true)
            }
            Some(_) => Err(BackendError::ActivityIdentityMismatch),
            None => Ok(false),
        }
    }

    fn token_context(&self) -> Result<TokenContext, BackendError> {
        self.token_context_for_account(self.selected_account_index)
    }

    fn token_context_for_account(&self, account_index: u8) -> Result<TokenContext, BackendError> {
        let wallet = self.unlocked.as_ref().ok_or(BackendError::Locked)?;
        let UnlockedWallet::V2(opened) = wallet else {
            return Err(BackendError::TokenRequiresV2);
        };
        validated_wallet_metadata(opened.wallet())?;
        let owner = opened
            .wallet()
            .account(usize::from(account_index))
            .ok_or(BackendError::UnsupportedAccount)?;
        let expected_index = u32::from(account_index);
        if owner.requested_index() != expected_index || owner.actual_index() != expected_index {
            return Err(BackendError::WalletMetadataInvalid);
        }
        Ok(TokenContext {
            account_index,
            owner: *owner.address().as_bytes(),
            vault_id: *opened.vault_id(),
            key: opened.derive_token_store_key(),
        })
    }

    fn activity_context(&self) -> Result<ActivityContext, BackendError> {
        let UnlockedWallet::V2(opened) = self.unlocked.as_ref().ok_or(BackendError::Locked)? else {
            return Err(BackendError::ActivityRequiresV2);
        };
        validated_wallet_metadata(opened.wallet())?;
        Ok(ActivityContext {
            vault_id: *opened.vault_id(),
            key: opened.derive_activity_store_key(),
        })
    }

    fn load_activity_store(
        &self,
        context: &ActivityContext,
    ) -> Result<LoadedActivityStore, BackendError> {
        let bytes = match read_activity_store_file(&self.activity_store_path)? {
            Some(bytes) => bytes,
            None => {
                return Ok(LoadedActivityStore {
                    store: ActivityStore::empty(context.vault_id)
                        .map_err(map_activity_store_error)?,
                    baseline: ActivityStoreBaseline {
                        bytes: None,
                        generation: 0,
                    },
                });
            }
        };
        let store = ActivityStore::open(bytes.as_slice(), &context.key, &context.vault_id)
            .map_err(map_activity_store_error)?;
        let wallet = self.unlocked.as_ref().ok_or(BackendError::Locked)?;
        for entry in store.entries() {
            if wallet.account_address(entry.identity().account_index())?
                != *entry.identity().sender()
            {
                return Err(BackendError::ActivityIdentityMismatch);
            }
        }
        let generation = store.generation();
        Ok(LoadedActivityStore {
            store,
            baseline: ActivityStoreBaseline {
                bytes: Some(bytes),
                generation,
            },
        })
    }

    fn activity_snapshots(
        &self,
        account_index: u8,
    ) -> Result<Vec<TransactionActivitySnapshot>, BackendError> {
        if matches!(self.unlocked, Some(UnlockedWallet::LegacyV1 { .. })) {
            return Ok(Vec::new());
        }
        let context = self.activity_context()?;
        let loaded = self.load_activity_store(&context)?;
        let mut snapshots = loaded
            .store
            .entries()
            .iter()
            .filter(|entry| entry.identity().account_index() == account_index)
            .map(activity_snapshot_from_entry)
            .collect::<Result<Vec<_>, _>>()?;
        snapshots.sort_by_key(|entry| std::cmp::Reverse(entry.submission_sequence));
        Ok(snapshots)
    }

    fn commit_submitted_activity(
        &self,
        activity_lease: &ActivityMutationLease<'_>,
        context: &ActivityContext,
        loaded: &mut LoadedActivityStore,
        identity: &TransactionIdentity,
    ) -> Result<TransactionActivitySnapshot, BackendError> {
        let mutation = loaded
            .store
            .upsert_submitted(identity)
            .map_err(map_activity_store_error)?;
        if mutation == ActivityMutation::Changed {
            self.persist_activity_store(
                activity_lease,
                context,
                &loaded.store,
                &loaded.baseline,
                identity.transaction_hash(),
            )?;
        }
        let entry = loaded
            .store
            .find(identity.transaction_hash())
            .filter(|entry| entry.identity() == identity)
            .ok_or(BackendError::ActivityIdentityMismatch)?;
        activity_snapshot_from_entry(entry)
    }

    fn persist_activity_store(
        &self,
        activity_lease: &ActivityMutationLease<'_>,
        context: &ActivityContext,
        store: &ActivityStore,
        baseline: &ActivityStoreBaseline,
        expected_hash: &[u8; 32],
    ) -> Result<(), BackendError> {
        #[cfg(test)]
        if self.fail_activity_persist_for_test {
            return Err(BackendError::ActivityStoreStorage);
        }
        let expected_generation = baseline
            .generation
            .checked_add(1)
            .ok_or(BackendError::ActivityStoreInvalid)?;
        if store.vault_id() != &context.vault_id
            || store.generation() != expected_generation
            || (baseline.bytes.is_none() != (baseline.generation == 0))
        {
            return Err(BackendError::ActivityStoreInvalid);
        }
        let current = read_activity_store_file(&self.activity_store_path)?;
        if current.as_deref() != baseline.bytes.as_deref() {
            return Err(BackendError::ActivityStoreChanged);
        }
        if let Some(current) = current.as_deref() {
            let reopened = ActivityStore::open(current, &context.key, &context.vault_id)
                .map_err(map_activity_store_error)?;
            if reopened.generation() != baseline.generation {
                return Err(BackendError::ActivityStoreChanged);
            }
        }
        let sealed = store.seal(&context.key).map_err(map_activity_store_error)?;
        let expected_identity = store
            .find(expected_hash)
            .map(ActivityEntry::identity)
            .ok_or(BackendError::ActivityIdentityMismatch)?;
        write_atomic_activity_store(activity_lease, &self.activity_store_path, sealed.as_slice())?;
        let readback =
            verify_exact_activity_store_readback(&self.activity_store_path, sealed.as_slice())?;
        let reopened = ActivityStore::open(&readback, &context.key, &context.vault_id)
            .map_err(map_activity_store_error)?;
        if reopened.generation() != expected_generation
            || reopened
                .find(expected_hash)
                .is_none_or(|entry| entry.identity() != expected_identity)
        {
            return Err(BackendError::ActivityStoreStorage);
        }
        Ok(())
    }

    fn ensure_token_mutation_allowed(&self) -> Result<(), BackendError> {
        if self.pending_broadcast_exists() {
            return Err(BackendError::PendingExists);
        }
        if self.prepared.is_some() {
            return Err(BackendError::TokenMutationBlocked);
        }
        if self.pending_generation.is_some() {
            return Err(BackendError::GenerationPending);
        }
        Ok(())
    }

    fn load_token_store(&self, context: &TokenContext) -> Result<LoadedTokenStore, BackendError> {
        let bytes = match read_token_store_file(&self.token_store_path)? {
            Some(bytes) => bytes,
            None => {
                return Ok(LoadedTokenStore {
                    store: TokenStore::empty(context.vault_id).map_err(map_token_store_error)?,
                    baseline: TokenStoreBaseline {
                        bytes: None,
                        generation: 0,
                    },
                });
            }
        };
        let store = TokenStore::open(bytes.as_slice(), &context.key, &context.vault_id)
            .map_err(map_token_store_error)?;
        let generation = store.generation();
        Ok(LoadedTokenStore {
            store,
            baseline: TokenStoreBaseline {
                bytes: Some(bytes),
                generation,
            },
        })
    }

    fn verify_token_store_baseline(
        &self,
        context: &TokenContext,
        baseline: &TokenStoreBaseline,
        expected_entry: &TokenEntry,
        permit: Option<&SessionPermit<'_>>,
    ) -> Result<(), BackendError> {
        let current = read_token_store_file(&self.token_store_path)?;
        ensure_optional_session_current(permit)?;
        if current.as_deref() != baseline.bytes.as_deref() {
            return Err(BackendError::TokenStoreChanged);
        }
        let bytes = current.as_deref().ok_or(BackendError::TokenStoreChanged)?;
        let reopened = TokenStore::open(bytes, &context.key, &context.vault_id)
            .map_err(map_token_store_error)?;
        ensure_optional_session_current(permit)?;
        if reopened.generation() != baseline.generation
            || !reopened
                .entries()
                .iter()
                .any(|entry| entry == expected_entry)
        {
            return Err(BackendError::TokenStoreChanged);
        }
        Ok(())
    }

    fn persist_token_store(
        &self,
        context: &TokenContext,
        store: &TokenStore,
        baseline: &TokenStoreBaseline,
    ) -> Result<(), BackendError> {
        let expected_generation = baseline
            .generation
            .checked_add(1)
            .ok_or(BackendError::TokenStoreInvalid)?;
        if store.vault_id() != &context.vault_id
            || store.generation() != expected_generation
            || (baseline.bytes.is_none() != (baseline.generation == 0))
        {
            return Err(BackendError::TokenStoreInvalid);
        }
        let sealed = store.seal(&context.key).map_err(map_token_store_error)?;
        let current = read_token_store_file(&self.token_store_path)?;
        if current.as_deref() != baseline.bytes.as_deref() {
            return Err(BackendError::TokenStoreChanged);
        }
        if let Some(current) = current.as_deref() {
            let reopened = TokenStore::open(current, &context.key, &context.vault_id)
                .map_err(map_token_store_error)?;
            if reopened.generation() != baseline.generation {
                return Err(BackendError::TokenStoreChanged);
            }
        }
        write_atomic_token_store(&self.token_store_path, sealed.as_slice())?;
        let readback =
            verify_exact_token_store_readback(&self.token_store_path, sealed.as_slice())?;
        let reopened = TokenStore::open(readback.as_slice(), &context.key, &context.vault_id)
            .map_err(map_token_store_error)?;
        if reopened.generation() != store.generation() || reopened.entries() != store.entries() {
            return Err(BackendError::TokenStoreInvalid);
        }
        Ok(())
    }

    fn inspect_token(
        &self,
        contract: [u8; 20],
        owner: [u8; 20],
        expected: Option<&TokenEntry>,
    ) -> Result<ValidatedToken, BackendError> {
        self.inspect_token_with_permit(contract, owner, expected, None)
    }

    fn inspect_token_with_permit(
        &self,
        contract: [u8; 20],
        owner: [u8; 20],
        expected: Option<&TokenEntry>,
        permit: Option<&SessionPermit<'_>>,
    ) -> Result<ValidatedToken, BackendError> {
        self.rpc
            .verify_sepolia()
            .map_err(|()| BackendError::RpcUnavailable)?;
        ensure_optional_session_current(permit)?;
        let code = self
            .rpc
            .contract_code(contract)
            .map_err(|()| BackendError::TokenQueryUnavailable)?;
        ensure_optional_session_current(permit)?;
        if code.is_empty() {
            return Err(BackendError::TokenContractEmpty);
        }
        let code_hash: [u8; 32] = Sha256::digest(code.as_slice()).into();
        if expected.is_some_and(|entry| entry.code_hash() != &code_hash) {
            return Err(BackendError::TokenCodeChanged);
        }

        let decimals_result = self
            .rpc
            .erc20_decimals(contract)
            .map_err(|()| BackendError::TokenQueryUnavailable)?;
        ensure_optional_session_current(permit)?;
        let decimals = erc20::decode_decimals(decimals_result.as_slice())
            .map_err(|_| BackendError::TokenMetadataInvalid)?;
        let symbol_result = self
            .rpc
            .erc20_symbol(contract)
            .map_err(|()| BackendError::TokenQueryUnavailable)?;
        ensure_optional_session_current(permit)?;
        let symbol = erc20::decode_symbol(symbol_result.as_slice())
            .map_err(|_| BackendError::TokenMetadataInvalid)?
            .map(|value| value.as_str().to_owned());
        if expected.is_some_and(|entry| {
            entry.decimals() != decimals || entry.symbol() != symbol.as_deref()
        }) {
            return Err(BackendError::TokenMetadataChanged);
        }

        let balance_result = self
            .rpc
            .erc20_balance_of(contract, owner)
            .map_err(|()| BackendError::TokenQueryUnavailable)?;
        ensure_optional_session_current(permit)?;
        let balance = erc20::decode_balance(balance_result.as_slice())
            .map_err(|_| BackendError::TokenMetadataInvalid)?;

        // Bookend the mutable chain reads. Direct bytecode or decoded metadata
        // drift while the calls are in flight must not produce a hybrid trusted
        // snapshot. Balance is intentionally not required to remain stable.
        // An implementation/storage change behind byte-identical proxy code is
        // outside this evidence and remains a documented limitation.
        let final_code = self
            .rpc
            .contract_code(contract)
            .map_err(|()| BackendError::TokenQueryUnavailable)?;
        ensure_optional_session_current(permit)?;
        let final_code_hash: [u8; 32] = Sha256::digest(final_code.as_slice()).into();
        if final_code.is_empty() || final_code_hash != code_hash {
            return Err(BackendError::TokenCodeChanged);
        }
        let final_decimals_result = self
            .rpc
            .erc20_decimals(contract)
            .map_err(|()| BackendError::TokenQueryUnavailable)?;
        ensure_optional_session_current(permit)?;
        let final_decimals = erc20::decode_decimals(final_decimals_result.as_slice())
            .map_err(|_| BackendError::TokenMetadataInvalid)?;
        let final_symbol_result = self
            .rpc
            .erc20_symbol(contract)
            .map_err(|()| BackendError::TokenQueryUnavailable)?;
        ensure_optional_session_current(permit)?;
        let final_symbol = erc20::decode_symbol(final_symbol_result.as_slice())
            .map_err(|_| BackendError::TokenMetadataInvalid)?
            .map(|value| value.as_str().to_owned());
        if final_decimals != decimals || final_symbol != symbol {
            return Err(BackendError::TokenMetadataChanged);
        }
        if expected.is_some_and(|entry| {
            entry.decimals() != final_decimals || entry.symbol() != final_symbol.as_deref()
        }) {
            return Err(BackendError::TokenMetadataChanged);
        }
        self.rpc
            .verify_sepolia()
            .map_err(|()| BackendError::RpcUnavailable)?;
        ensure_optional_session_current(permit)?;
        Ok(ValidatedToken {
            contract,
            decimals: final_decimals,
            symbol: final_symbol,
            code_hash,
            balance,
        })
    }

    fn token_views(&self, context: &TokenContext, store: &TokenStore) -> Vec<CustomTokenSnapshot> {
        store
            .entries()
            .iter()
            .map(|entry| {
                let contract_address = checksum_address(*entry.contract());
                match self.inspect_token(*entry.contract(), context.owner, Some(entry)) {
                    Ok(validated) => {
                        match erc20::format_token_amount(validated.balance, validated.decimals) {
                            Ok(balance) => CustomTokenSnapshot {
                                contract_address,
                                state: CustomTokenState::Verified {
                                    symbol: validated.symbol,
                                    decimals: validated.decimals,
                                    balance,
                                },
                            },
                            Err(_) => CustomTokenSnapshot {
                                contract_address,
                                state: CustomTokenState::Unavailable {
                                    reason_ko: error_text(BackendError::TokenMetadataInvalid),
                                },
                            },
                        }
                    }
                    Err(error) => CustomTokenSnapshot {
                        contract_address,
                        state: CustomTokenState::Unavailable {
                            reason_ko: error_text(error),
                        },
                    },
                }
            })
            .collect()
    }

    fn refresh_custom_tokens_inner(&self) -> Result<Vec<CustomTokenSnapshot>, BackendError> {
        let context = self.token_context()?;
        self.rpc
            .verify_sepolia()
            .map_err(|()| BackendError::RpcUnavailable)?;
        let loaded = self.load_token_store(&context)?;
        Ok(self.token_views(&context, &loaded.store))
    }

    fn add_custom_token_inner(
        &mut self,
        contract_address: &str,
    ) -> Result<Vec<CustomTokenSnapshot>, BackendError> {
        self.ensure_token_mutation_allowed()?;
        let context = self.token_context()?;
        let contract = parse_address(contract_address)
            .map_err(|_| BackendError::TokenContractAddressInvalid)?;
        let _lease = TokenMutationLease::acquire(&self.token_store_path)?;
        self.rpc
            .verify_sepolia()
            .map_err(|()| BackendError::RpcUnavailable)?;
        let mut loaded = self.load_token_store(&context)?;
        if loaded
            .store
            .entries()
            .iter()
            .any(|entry| entry.contract() == &contract)
        {
            return Err(BackendError::TokenDuplicate);
        }
        let validated = self.inspect_token(contract, context.owner, None)?;
        let entry = TokenEntry::new(
            validated.contract,
            validated.decimals,
            validated.symbol,
            validated.code_hash,
        )
        .map_err(map_token_store_error)?;
        loaded.store.add(entry).map_err(map_token_store_error)?;
        let committed_entry = loaded
            .store
            .entries()
            .iter()
            .find(|entry| entry.contract() == &contract)
            .ok_or(BackendError::TokenStoreInvalid)?;
        // Revalidate the exact identity immediately before committing. The
        // post-commit view performs the same check again before exposing any
        // metadata or balance to the UI.
        self.inspect_token(contract, context.owner, Some(committed_entry))?;
        self.ensure_token_mutation_allowed()?;
        self.persist_token_store(&context, &loaded.store, &loaded.baseline)?;
        Ok(self.token_views(&context, &loaded.store))
    }

    fn remove_custom_token_inner(
        &mut self,
        contract_address: &str,
    ) -> Result<Vec<CustomTokenSnapshot>, BackendError> {
        self.ensure_token_mutation_allowed()?;
        let context = self.token_context()?;
        let contract = parse_address(contract_address)
            .map_err(|_| BackendError::TokenContractAddressInvalid)?;
        let _lease = TokenMutationLease::acquire(&self.token_store_path)?;
        self.rpc
            .verify_sepolia()
            .map_err(|()| BackendError::RpcUnavailable)?;
        let mut loaded = self.load_token_store(&context)?;
        loaded
            .store
            .remove(contract)
            .map_err(map_token_store_error)?;
        self.ensure_token_mutation_allowed()?;
        self.persist_token_store(&context, &loaded.store, &loaded.baseline)?;
        Ok(self.token_views(&context, &loaded.store))
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
        if matches!(wallet, UnlockedWallet::LegacyV1 { .. }) {
            return Err(BackendError::ActivityRequiresV2);
        }
        if self.pending_broadcast_exists() {
            return Err(BackendError::PendingExists);
        }
        let (account_index, sender) = self.selected_account()?;
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
            sender_account_index: account_index,
            sender_address: checksum_address(sender),
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
        self.prepared = Some(PreparedTransfer::Native(PreparedNativeTransfer {
            account_index,
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
        }));
        Ok(preview)
    }

    fn prepare_saved_erc20_transfer_inner(
        &mut self,
        contract_address: &str,
        recipient: &str,
        amount_text: &str,
        fee_selection: FeeSelection,
        permit: &SessionPermit<'_>,
    ) -> Result<Erc20TransferPreview, BackendError> {
        ensure_session_current(permit)?;
        // Failed re-preparation must never leave an older signer-ready value.
        self.prepared = None;
        if self.pending_broadcast_exists() {
            ensure_session_current(permit)?;
            return Err(BackendError::PendingExists);
        }
        ensure_session_current(permit)?;
        let (account_index, sender) = self.selected_account()?;
        let context = self.token_context()?;
        if context.account_index != account_index || context.owner != sender {
            return Err(BackendError::PreparedInvalid);
        }
        let contract = parse_address(contract_address)
            .map_err(|_| BackendError::TokenContractAddressInvalid)?;
        let recipient = parse_address(recipient)?;

        // The UI contract is only a lookup key. Resolve all authoritative token
        // metadata from a freshly authenticated sidecar.
        let loaded = self.load_token_store(&context)?;
        ensure_session_current(permit)?;
        let saved_entry = loaded
            .store
            .entries()
            .iter()
            .find(|entry| entry.contract() == &contract)
            .cloned()
            .ok_or(BackendError::TokenNotFound)?;
        let initial =
            self.inspect_token_with_permit(contract, sender, Some(&saved_entry), Some(permit))?;
        let amount = erc20::parse_token_amount(amount_text, saved_entry.decimals())
            .map_err(|_| BackendError::InvalidAmount)?;
        if amount > initial.balance {
            return Err(BackendError::InsufficientTokenBalance);
        }

        let nonce = self
            .rpc
            .pending_nonce(sender)
            .map_err(|()| BackendError::RpcUnavailable)?;
        ensure_session_current(permit)?;
        let quote = self
            .rpc
            .fee_quote()
            .map_err(|()| BackendError::RpcUnavailable)?;
        ensure_session_current(permit)?;
        let fee_plan = resolve_fee_plan(fee_selection, quote)?;
        let quote_expires_at = self
            .clock
            .now()
            .checked_add(FEE_QUOTE_TTL)
            .ok_or(BackendError::PreparedInvalid)?;

        let estimated_gas_word = self
            .rpc
            .estimate_erc20_transfer_gas(
                sender,
                contract,
                recipient,
                amount,
                nonce,
                fee_plan.priority_fee,
                fee_plan.maximum_fee,
            )
            .map_err(|()| BackendError::TokenGasEstimateInvalid)?;
        ensure_session_current(permit)?;
        let estimated_gas = estimated_gas_word
            .to_u64()
            .ok_or(BackendError::TokenGasEstimateInvalid)?;
        let gas_limit = erc20::token_gas_limit(estimated_gas)
            .map(Word::from_u64)
            .map_err(|_| BackendError::TokenGasEstimateInvalid)?;
        let preflight = self
            .rpc
            .erc20_transfer_preflight(
                sender,
                contract,
                recipient,
                amount,
                nonce,
                gas_limit,
                fee_plan.priority_fee,
                fee_plan.maximum_fee,
            )
            .map_err(|()| BackendError::TokenTransferRejected)?;
        ensure_session_current(permit)?;
        erc20::validate_transfer_result(preflight.as_slice())
            .map_err(|_| BackendError::TokenTransferRejected)?;
        let estimated_gas_price = fee_plan
            .quoted_base_fee
            .checked_add(fee_plan.priority_fee)
            .ok_or(BackendError::FeeLimit)?;
        let estimated_network_fee = estimated_gas_price
            .checked_mul_u64(estimated_gas)
            .ok_or(BackendError::FeeLimit)?;
        let maximum_network_fee = fee_plan
            .maximum_fee
            .checked_mul_u64(gas_limit.to_u64().ok_or(BackendError::PreparedInvalid)?)
            .ok_or(BackendError::FeeLimit)?;
        let native_balance = self
            .rpc
            .pending_balance(sender)
            .map_err(|()| BackendError::BalanceUnavailable)?;
        ensure_session_current(permit)?;
        if maximum_network_fee > native_balance {
            return Err(BackendError::InsufficientBalance);
        }

        // Full chain and sidecar bookends surround nonce, balances, preflight,
        // and estimate. They reject ordinary sidecar changes and direct
        // bytecode/metadata drift rather than claiming atomic chain state or
        // visibility into a byte-identical proxy implementation upgrade.
        let final_token =
            self.inspect_token_with_permit(contract, sender, Some(&saved_entry), Some(permit))?;
        if final_token.code_hash != initial.code_hash
            || final_token.decimals != initial.decimals
            || final_token.symbol != initial.symbol
            || amount > final_token.balance
        {
            return Err(BackendError::TokenMetadataChanged);
        }
        self.verify_token_store_baseline(&context, &loaded.baseline, &saved_entry, Some(permit))?;
        ensure_quote_live(self.clock.as_ref(), quote_expires_at)?;
        // Final permit check immediately before freezing signer-ready state.
        ensure_session_current(permit)?;
        let remaining_quote_seconds =
            conservative_remaining_quote_seconds(self.clock.as_ref(), quote_expires_at)?;
        let normalized_amount = erc20::format_token_amount(amount, saved_entry.decimals())
            .map_err(|_| BackendError::InvalidAmount)?;
        let preview = Erc20TransferPreview {
            sender_account_index: account_index,
            sender_address: checksum_address(sender),
            contract_address: checksum_address(contract),
            symbol: saved_entry.symbol().map(str::to_owned),
            decimals: saved_entry.decimals(),
            recipient: checksum_address(recipient),
            amount: normalized_amount,
            nonce: decimal_string(nonce),
            fee_mode_ko: fee_plan.mode_label.to_owned(),
            estimated_gas: estimated_gas.to_string(),
            gas_limit: decimal_string(gas_limit),
            quoted_base_fee_per_gas_gwei: format_gwei(fee_plan.quoted_base_fee),
            max_priority_fee_per_gas_gwei: format_gwei(fee_plan.priority_fee),
            max_fee_per_gas_gwei: format_gwei(fee_plan.maximum_fee),
            estimated_network_fee_eth: format_ether(estimated_network_fee),
            max_network_fee_eth: format_ether(maximum_network_fee),
            quote_valid_for_seconds: remaining_quote_seconds.to_string(),
        };
        self.prepared = Some(PreparedTransfer::SavedErc20(PreparedErc20Transfer {
            account_index,
            sender,
            recipient,
            contract,
            amount,
            saved_entry,
            token_store_baseline: loaded.baseline,
            nonce,
            estimated_gas,
            gas_limit,
            quoted_base_fee: fee_plan.quoted_base_fee,
            priority_fee: fee_plan.priority_fee,
            maximum_fee: fee_plan.maximum_fee,
            estimated_network_fee,
            maximum_network_fee,
            quote_expires_at,
        }));
        Ok(preview)
    }

    fn confirm_prepared_with_permit(
        &mut self,
        permit: &SessionPermit<'_>,
    ) -> Result<SendReceipt, BackendError> {
        ensure_session_current(permit)?;
        let pending_exists = self.pending_broadcast_exists();
        ensure_session_current(permit)?;
        if pending_exists {
            self.prepared = None;
            return Err(BackendError::PendingExists);
        }
        let prepared = self
            .prepared
            .take()
            .ok_or(BackendError::NoPreparedTransfer)?;
        let prepared = match prepared {
            PreparedTransfer::Native(prepared) => prepared,
            PreparedTransfer::SavedErc20(prepared) => {
                return self.confirm_saved_erc20_transfer(prepared, permit);
            }
        };
        let wallet = self.unlocked.as_ref().ok_or(BackendError::Locked)?;
        let wallet_address = wallet.account_address(prepared.account_index)?;
        let expected_estimated_gas_price =
            prepared.quoted_base_fee.checked_add(prepared.priority_fee);
        if self.selected_account_index != prepared.account_index
            || wallet_address != prepared.sender
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
        ensure_session_current(permit)?;
        let current_nonce = self
            .rpc
            .pending_nonce(prepared.sender)
            .map_err(|()| BackendError::RpcUnavailable)?;
        ensure_session_current(permit)?;
        if current_nonce != prepared.nonce {
            return Err(BackendError::AccountChanged);
        }
        let current_base_fee = self
            .rpc
            .latest_base_fee()
            .map_err(|()| BackendError::RpcUnavailable)?;
        ensure_session_current(permit)?;
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
        ensure_session_current(permit)?;
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
        ensure_session_current(permit)?;
        if estimated_gas != prepared.gas_limit {
            return Err(BackendError::UnsupportedTransfer);
        }
        ensure_quote_live(self.clock.as_ref(), prepared.quote_expires_at)?;
        // Revocation during any preflight RPC must stop before a signature is
        // created. This is the first irreversible capability boundary.
        ensure_session_current(permit)?;
        let activity_context = self.activity_context()?;
        let activity_lease = ActivityMutationLease::acquire(&self.activity_store_path)?;
        let mut activity_loaded = self.load_activity_store(&activity_context)?;
        if activity_loaded.store.entries().len() >= ACTIVITY_CAPACITY {
            return Err(BackendError::ActivityCapacity);
        }
        activity_loaded
            .store
            .ensure_nonce_available(
                prepared.account_index,
                &prepared.sender,
                prepared.nonce.as_be_bytes(),
            )
            .map_err(map_activity_store_error)?;
        ensure_session_current(permit)?;
        #[cfg(test)]
        {
            self.sign_attempts += 1;
        }
        let signed = match wallet {
            UnlockedWallet::LegacyV1 { .. } => return Err(BackendError::ActivityRequiresV2),
            UnlockedWallet::V2(opened) => {
                let private_key = opened
                    .wallet()
                    .account_private_key(u32::from(prepared.account_index))
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
        // A signature created concurrently with revocation must not be made
        // durable unless this request is still current.
        ensure_session_current(permit)?;
        write_new_pending(
            &self.pending_path,
            signed.transaction_hash,
            signed.bytes.as_slice(),
        )?;
        let mut pending_lease = PendingFileLease::open(&self.pending_path)?;
        verify_pending_lease(
            &mut pending_lease,
            signed.transaction_hash,
            signed.bytes.as_slice(),
        )?;
        // This is both the post-write check and the final local commit point
        // before the externally visible RPC send. Revocation leaves the exact
        // signed record durable for authenticated recovery.
        ensure_session_current(permit)?;
        let returned_hash = guarded_broadcast(self.rpc.as_ref(), signed.bytes.as_slice(), permit)?;
        if returned_hash != signed.transaction_hash {
            return Err(BackendError::HashMismatch);
        }
        ensure_session_current(permit)?;
        let identity = TransactionIdentity::native(
            signed.transaction_hash,
            prepared.sender,
            prepared.account_index,
            *prepared.nonce.as_be_bytes(),
            *prepared.gas_limit.as_be_bytes(),
            *prepared.priority_fee.as_be_bytes(),
            *prepared.maximum_fee.as_be_bytes(),
            prepared.recipient,
            *prepared.value.as_be_bytes(),
        )
        .map_err(map_activity_store_error)?;
        let activity = self.commit_submitted_activity(
            &activity_lease,
            &activity_context,
            &mut activity_loaded,
            &identity,
        )?;
        // A lock racing with the transport call cannot undo its external side
        // effect. Check immediately before deletion and preserve the pending
        // record instead of claiming local resolution when send went stale.
        ensure_session_current(permit)?;
        verify_pending_lease(
            &mut pending_lease,
            signed.transaction_hash,
            signed.bytes.as_slice(),
        )?;
        pending_lease.delete_exact(&self.pending_path)?;
        self.last_balance = None;
        Ok(SendReceipt {
            transaction_hash: fixed_hex(&returned_hash),
            activity: Some(activity),
            broadcast_performed: true,
        })
    }

    fn confirm_saved_erc20_transfer(
        &mut self,
        prepared: PreparedErc20Transfer,
        permit: &SessionPermit<'_>,
    ) -> Result<SendReceipt, BackendError> {
        ensure_session_current(permit)?;
        let wallet = self.unlocked.as_ref().ok_or(BackendError::Locked)?;
        let wallet_address = wallet.account_address(prepared.account_index)?;
        let expected_gas_limit = erc20::token_gas_limit(prepared.estimated_gas)
            .map(Word::from_u64)
            .map_err(|_| BackendError::PreparedInvalid)?;
        let gas_limit_u64 = prepared
            .gas_limit
            .to_u64()
            .ok_or(BackendError::PreparedInvalid)?;
        let expected_estimated_fee = prepared
            .quoted_base_fee
            .checked_add(prepared.priority_fee)
            .and_then(|price| price.checked_mul_u64(prepared.estimated_gas));
        if self.selected_account_index != prepared.account_index
            || wallet_address != prepared.sender
            || prepared.recipient == [0; 20]
            || prepared.contract == [0; 20]
            || prepared.amount.is_zero()
            || prepared.saved_entry.contract() != &prepared.contract
            || prepared.saved_entry.code_hash() == &[0; 32]
            || prepared.gas_limit != expected_gas_limit
            || validate_fee_values(
                prepared.quoted_base_fee,
                prepared.priority_fee,
                prepared.maximum_fee,
            )
            .is_err()
            || expected_estimated_fee != Some(prepared.estimated_network_fee)
            || prepared.maximum_fee.checked_mul_u64(gas_limit_u64)
                != Some(prepared.maximum_network_fee)
        {
            return Err(BackendError::PreparedInvalid);
        }
        ensure_quote_live(self.clock.as_ref(), prepared.quote_expires_at)?;
        let context = self.token_context()?;
        if context.account_index != prepared.account_index || context.owner != prepared.sender {
            return Err(BackendError::PreparedInvalid);
        }

        // Initial authenticated sidecar + full contract identity bookend.
        self.verify_token_store_baseline(
            &context,
            &prepared.token_store_baseline,
            &prepared.saved_entry,
            Some(permit),
        )?;
        let initial = self.inspect_token_with_permit(
            prepared.contract,
            prepared.sender,
            Some(&prepared.saved_entry),
            Some(permit),
        )?;
        if prepared.amount > initial.balance {
            return Err(BackendError::InsufficientTokenBalance);
        }

        let current_nonce = self
            .rpc
            .pending_nonce(prepared.sender)
            .map_err(|()| BackendError::RpcUnavailable)?;
        ensure_session_current(permit)?;
        if current_nonce != prepared.nonce {
            return Err(BackendError::AccountChanged);
        }
        let current_base_fee = self
            .rpc
            .latest_base_fee()
            .map_err(|()| BackendError::RpcUnavailable)?;
        ensure_session_current(permit)?;
        if validate_fee_values(
            current_base_fee,
            prepared.priority_fee,
            prepared.maximum_fee,
        )
        .is_err()
        {
            return Err(BackendError::QuoteChanged);
        }
        let native_balance = self
            .rpc
            .pending_balance(prepared.sender)
            .map_err(|()| BackendError::BalanceUnavailable)?;
        ensure_session_current(permit)?;
        if prepared.maximum_network_fee > native_balance {
            return Err(BackendError::InsufficientBalance);
        }
        let estimated_gas = self
            .rpc
            .estimate_erc20_transfer_gas(
                prepared.sender,
                prepared.contract,
                prepared.recipient,
                prepared.amount,
                prepared.nonce,
                prepared.priority_fee,
                prepared.maximum_fee,
            )
            .map_err(|()| BackendError::TokenGasEstimateInvalid)?;
        ensure_session_current(permit)?;
        if estimated_gas.to_u64() != Some(prepared.estimated_gas) {
            return Err(BackendError::TokenGasEstimateInvalid);
        }
        let preflight = self
            .rpc
            .erc20_transfer_preflight(
                prepared.sender,
                prepared.contract,
                prepared.recipient,
                prepared.amount,
                prepared.nonce,
                prepared.gas_limit,
                prepared.priority_fee,
                prepared.maximum_fee,
            )
            .map_err(|()| BackendError::TokenTransferRejected)?;
        ensure_session_current(permit)?;
        erc20::validate_transfer_result(preflight.as_slice())
            .map_err(|_| BackendError::TokenTransferRejected)?;

        // Final chain and sidecar bookends immediately before signing.
        let final_token = self.inspect_token_with_permit(
            prepared.contract,
            prepared.sender,
            Some(&prepared.saved_entry),
            Some(permit),
        )?;
        if final_token.code_hash != initial.code_hash
            || final_token.decimals != initial.decimals
            || final_token.symbol != initial.symbol
            || prepared.amount > final_token.balance
        {
            return Err(BackendError::TokenMetadataChanged);
        }
        self.verify_token_store_baseline(
            &context,
            &prepared.token_store_baseline,
            &prepared.saved_entry,
            Some(permit),
        )?;
        ensure_quote_live(self.clock.as_ref(), prepared.quote_expires_at)?;
        ensure_session_current(permit)?;
        let activity_context = self.activity_context()?;
        let activity_lease = ActivityMutationLease::acquire(&self.activity_store_path)?;
        let mut activity_loaded = self.load_activity_store(&activity_context)?;
        if activity_loaded.store.entries().len() >= ACTIVITY_CAPACITY {
            return Err(BackendError::ActivityCapacity);
        }
        activity_loaded
            .store
            .ensure_nonce_available(
                prepared.account_index,
                &prepared.sender,
                prepared.nonce.as_be_bytes(),
            )
            .map_err(map_activity_store_error)?;
        ensure_session_current(permit)?;
        #[cfg(test)]
        {
            self.sign_attempts += 1;
        }
        let signed = match wallet {
            UnlockedWallet::LegacyV1 { .. } => return Err(BackendError::TokenRequiresV2),
            UnlockedWallet::V2(opened) => {
                let account_signer = opened
                    .wallet()
                    .account_private_key(u32::from(prepared.account_index))
                    .map_err(map_secret_error)?;
                sign_erc20_type_two(
                    account_signer.as_bytes(),
                    prepared.sender,
                    prepared.contract,
                    prepared.recipient,
                    prepared.amount,
                    prepared.nonce,
                    prepared.gas_limit,
                    prepared.priority_fee,
                    prepared.maximum_fee,
                )?
            }
        };
        ensure_session_current(permit)?;
        write_new_pending(
            &self.pending_path,
            signed.transaction_hash,
            signed.bytes.as_slice(),
        )?;
        let mut pending_lease = PendingFileLease::open(&self.pending_path)?;
        verify_pending_lease(
            &mut pending_lease,
            signed.transaction_hash,
            signed.bytes.as_slice(),
        )?;
        ensure_session_current(permit)?;
        let returned_hash = guarded_broadcast(self.rpc.as_ref(), signed.bytes.as_slice(), permit)?;
        if returned_hash != signed.transaction_hash {
            return Err(BackendError::HashMismatch);
        }
        ensure_session_current(permit)?;
        let identity = TransactionIdentity::erc20(
            signed.transaction_hash,
            prepared.sender,
            prepared.account_index,
            *prepared.nonce.as_be_bytes(),
            *prepared.gas_limit.as_be_bytes(),
            *prepared.priority_fee.as_be_bytes(),
            *prepared.maximum_fee.as_be_bytes(),
            prepared.contract,
            prepared.recipient,
            *prepared.amount.as_be_bytes(),
            prepared.saved_entry.decimals(),
            prepared.saved_entry.symbol().map(str::to_owned),
        )
        .map_err(map_activity_store_error)?;
        let activity = self.commit_submitted_activity(
            &activity_lease,
            &activity_context,
            &mut activity_loaded,
            &identity,
        )?;
        ensure_session_current(permit)?;
        verify_pending_lease(
            &mut pending_lease,
            signed.transaction_hash,
            signed.bytes.as_slice(),
        )?;
        pending_lease.delete_exact(&self.pending_path)?;
        self.last_balance = None;
        Ok(SendReceipt {
            transaction_hash: fixed_hex(&returned_hash),
            activity: Some(activity),
            broadcast_performed: true,
        })
    }

    #[cfg(test)]
    fn confirm_prepared_inner(&mut self) -> Result<SendReceipt, BackendError> {
        let active_epoch = std::sync::atomic::AtomicU64::new(0);
        let permit = SessionPermit::current_for_test(0, &active_epoch);
        self.confirm_prepared_with_permit(&permit)
    }

    fn cancel_prepared_inner(&mut self) {
        self.prepared = None;
    }

    fn prepare_pending_retry(
        &mut self,
        permit: Option<&SessionPermit<'_>>,
    ) -> Result<PendingBroadcastPreview, BackendError> {
        ensure_optional_session_current(permit)?;
        if self.unlocked.is_none() {
            return Err(BackendError::Locked);
        }
        if self.prepared.is_some() {
            return Err(BackendError::AccountSwitchBlocked);
        }
        self.prepared_pending_retry = None;
        let mut lease = PendingFileLease::open(&self.pending_path)?;
        let pending = lease.read_record()?;
        ensure_optional_session_current(permit)?;
        let (sender_account_index, sender) =
            self.attribute_pending_sender(pending.raw_transaction.as_slice())?;
        ensure_optional_session_current(permit)?;
        let prepared = PreparedPendingRetry {
            sender_account_index,
            sender,
            transaction_hash: pending.transaction_hash,
            raw_transaction: pending.raw_transaction,
            lease,
        };
        let preview = prepared.preview();
        self.prepared_pending_retry = Some(prepared);
        Ok(preview)
    }

    fn attribute_pending_sender(
        &self,
        raw_transaction: &[u8],
    ) -> Result<(u8, [u8; 20]), BackendError> {
        let wallet = self.unlocked.as_ref().ok_or(BackendError::Locked)?;
        let recovered = recover_signed_type_two_sender(raw_transaction)?;
        let (_, _, account_count) = wallet.validated_metadata()?;
        let mut matched = None;
        for index in 0..account_count {
            if wallet.account_address(index)? == recovered {
                if matched.is_some() {
                    return Err(BackendError::PendingAccountMismatch);
                }
                matched = Some(index);
            }
        }
        matched
            .map(|index| (index, recovered))
            .ok_or(BackendError::PendingAccountMismatch)
    }

    fn pending_activity_identity(
        &self,
        prepared: &PreparedPendingRetry,
    ) -> Result<TransactionIdentity, BackendError> {
        let decoded = decode_pending_activity(prepared.raw_transaction.as_slice())?;
        match decoded.transfer {
            DecodedPendingTransfer::Native { recipient, value } => TransactionIdentity::native(
                prepared.transaction_hash,
                prepared.sender,
                prepared.sender_account_index,
                *decoded.nonce.as_be_bytes(),
                *decoded.gas_limit.as_be_bytes(),
                *decoded.priority_fee.as_be_bytes(),
                *decoded.maximum_fee.as_be_bytes(),
                recipient,
                *value.as_be_bytes(),
            )
            .map_err(map_activity_store_error),
            DecodedPendingTransfer::Erc20 {
                contract,
                recipient,
                raw_amount,
            } => {
                let token_context =
                    self.token_context_for_account(prepared.sender_account_index)?;
                if token_context.owner != prepared.sender {
                    return Err(BackendError::PendingAccountMismatch);
                }
                let loaded = self.load_token_store(&token_context)?;
                let saved = loaded
                    .store
                    .entries()
                    .iter()
                    .find(|entry| entry.contract() == &contract)
                    .ok_or(BackendError::TokenNotFound)?;
                TransactionIdentity::erc20(
                    prepared.transaction_hash,
                    prepared.sender,
                    prepared.sender_account_index,
                    *decoded.nonce.as_be_bytes(),
                    *decoded.gas_limit.as_be_bytes(),
                    *decoded.priority_fee.as_be_bytes(),
                    *decoded.maximum_fee.as_be_bytes(),
                    contract,
                    recipient,
                    raw_amount,
                    saved.decimals(),
                    saved.symbol().map(str::to_owned),
                )
                .map_err(map_activity_store_error)
            }
        }
    }

    fn verify_frozen_pending(
        &self,
        prepared: &mut PreparedPendingRetry,
        permit: &SessionPermit<'_>,
    ) -> Result<(), BackendError> {
        ensure_session_current(permit)?;
        let current = prepared.lease.read_record()?;
        if current.transaction_hash != prepared.transaction_hash
            || current.raw_transaction.as_slice() != prepared.raw_transaction.as_slice()
        {
            return Err(BackendError::PendingChanged);
        }
        let (account_index, sender) =
            self.attribute_pending_sender(current.raw_transaction.as_slice())?;
        if account_index != prepared.sender_account_index || sender != prepared.sender {
            return Err(BackendError::PendingChanged);
        }
        ensure_session_current(permit)
    }

    fn retry_pending_with_permit(
        &mut self,
        permit: &SessionPermit<'_>,
    ) -> Result<SendReceipt, BackendError> {
        ensure_session_current(permit)?;
        if self.unlocked.is_none() {
            return Err(BackendError::Locked);
        }
        if self.prepared.is_some() {
            return Err(BackendError::AccountSwitchBlocked);
        }
        let mut prepared = self
            .prepared_pending_retry
            .take()
            .ok_or(BackendError::NoPreparedPending)?;
        self.verify_frozen_pending(&mut prepared, permit)?;
        let activity_context = self.activity_context()?;
        let identity = self.pending_activity_identity(&prepared)?;
        if identity.transaction_hash() != &prepared.transaction_hash
            || identity.sender() != &prepared.sender
            || identity.account_index() != prepared.sender_account_index
        {
            return Err(BackendError::ActivityIdentityMismatch);
        }
        let activity_lease = ActivityMutationLease::acquire(&self.activity_store_path)?;
        let mut activity_loaded = self.load_activity_store(&activity_context)?;
        activity_loaded
            .store
            .can_upsert(&identity)
            .map_err(map_activity_store_error)?;
        if let Some(committed) = activity_loaded.store.find(identity.transaction_hash()) {
            if committed.identity() != &identity {
                return Err(BackendError::ActivityIdentityMismatch);
            }
            let activity = activity_snapshot_from_entry(committed)?;
            // A previous attempt committed activity but could not clean the
            // pending file. Reverify and remove that same open object without
            // any network call or rebroadcast.
            self.verify_frozen_pending(&mut prepared, permit)?;
            prepared.lease.delete_exact(&self.pending_path)?;
            self.last_balance = None;
            return Ok(SendReceipt {
                transaction_hash: fixed_hex(identity.transaction_hash()),
                activity: Some(activity),
                broadcast_performed: false,
            });
        }
        self.verify_frozen_pending(&mut prepared, permit)?;
        if self.pending_transaction_is_observed(
            &identity,
            prepared.raw_transaction.as_slice(),
            permit,
        )? {
            let activity = self.commit_submitted_activity(
                &activity_lease,
                &activity_context,
                &mut activity_loaded,
                &identity,
            )?;
            self.verify_frozen_pending(&mut prepared, permit)?;
            prepared.lease.delete_exact(&self.pending_path)?;
            self.last_balance = None;
            return Ok(SendReceipt {
                transaction_hash: fixed_hex(identity.transaction_hash()),
                activity: Some(activity),
                broadcast_performed: false,
            });
        }
        // Reopen and compare the durable record at the final local commit
        // point. Only the independently frozen bytes are ever broadcast.
        self.verify_frozen_pending(&mut prepared, permit)?;
        let returned_hash = guarded_broadcast(
            self.rpc.as_ref(),
            prepared.raw_transaction.as_slice(),
            permit,
        )?;
        if returned_hash != prepared.transaction_hash {
            return Err(BackendError::HashMismatch);
        }
        ensure_session_current(permit)?;
        let activity = self.commit_submitted_activity(
            &activity_lease,
            &activity_context,
            &mut activity_loaded,
            &identity,
        )?;
        // A matching node response cannot authorize deleting a record that
        // was replaced while the request was in flight.
        self.verify_frozen_pending(&mut prepared, permit)?;
        prepared.lease.delete_exact(&self.pending_path)?;
        self.last_balance = None;
        Ok(SendReceipt {
            transaction_hash: fixed_hex(&returned_hash),
            activity: Some(activity),
            broadcast_performed: true,
        })
    }

    #[cfg(test)]
    fn retry_pending_inner(&mut self) -> Result<SendReceipt, BackendError> {
        let active_epoch = std::sync::atomic::AtomicU64::new(0);
        let permit = SessionPermit::current_for_test(0, &active_epoch);
        self.prepare_pending_retry(Some(&permit))?;
        self.retry_pending_with_permit(&permit)
    }
}

impl WalletBackend for DemoBackend {
    fn begin_generate_wallet(
        &mut self,
        words: NewMnemonicWords,
        password: SensitiveText,
        password_confirmation: SensitiveText,
    ) -> Result<GeneratedBackupReveal, String> {
        self.begin_generate(words, password, password_confirmation)
            .map_err(error_text)
    }

    fn begin_generated_backup_challenge(&mut self) -> Result<GeneratedBackupChallenge, String> {
        self.begin_generated_challenge().map_err(error_text)
    }

    fn confirm_generated_wallet(
        &mut self,
        confirmation: GeneratedBackupConfirmation,
        permit: &SessionPermit<'_>,
    ) -> Result<WalletSnapshot, String> {
        self.confirm_generated(confirmation, permit)
            .map_err(error_text)
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

    fn lock_wallet(&mut self) {
        self.lock();
    }

    fn select_account(&mut self, index: u8) -> Result<WalletSnapshot, String> {
        self.select_account_inner(index).map_err(error_text)
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

    fn refresh_activity(
        &mut self,
        transaction_hash: &str,
        permit: &SessionPermit<'_>,
    ) -> Result<TransactionActivitySnapshot, String> {
        self.refresh_activity_inner(transaction_hash, permit)
            .map_err(error_text)
    }

    fn add_custom_token(
        &mut self,
        contract_address: &str,
    ) -> Result<Vec<CustomTokenSnapshot>, String> {
        self.add_custom_token_inner(contract_address)
            .map_err(error_text)
    }

    fn refresh_custom_tokens(&mut self) -> Result<Vec<CustomTokenSnapshot>, String> {
        self.refresh_custom_tokens_inner().map_err(error_text)
    }

    fn remove_custom_token(
        &mut self,
        contract_address: &str,
    ) -> Result<Vec<CustomTokenSnapshot>, String> {
        self.remove_custom_token_inner(contract_address)
            .map_err(error_text)
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

    fn prepare_saved_erc20_transfer(
        &mut self,
        contract_address: &str,
        recipient: &str,
        amount: &str,
        fee_selection: FeeSelection,
        permit: &SessionPermit<'_>,
    ) -> Result<Erc20TransferPreview, String> {
        self.prepare_saved_erc20_transfer_inner(
            contract_address,
            recipient,
            amount,
            fee_selection,
            permit,
        )
        .map_err(error_text)
    }

    fn confirm_prepared(&mut self, permit: &SessionPermit<'_>) -> Result<SendReceipt, String> {
        self.confirm_prepared_with_permit(permit)
            .map_err(error_text)
    }

    fn cancel_prepared(&mut self) -> Result<(), String> {
        self.cancel_prepared_inner();
        Ok(())
    }

    fn inspect_pending_broadcast(
        &mut self,
        permit: &SessionPermit<'_>,
    ) -> Result<PendingBroadcastPreview, String> {
        DemoBackend::inspect_pending_broadcast(self, permit)
    }

    fn retry_pending(&mut self, permit: &SessionPermit<'_>) -> Result<SendReceipt, String> {
        DemoBackend::retry_pending(self, permit)
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

    fn latest_nonce(&self, address: [u8; 20]) -> Result<Word, ()> {
        self.0
            .latest_nonce(rpc::Address20::new(address))
            .map(|value| Word::from_be_bytes(*value.as_be_bytes()))
            .map_err(|_| ())
    }

    fn activity_transaction(
        &self,
        transaction_hash: [u8; 32],
    ) -> Result<Option<ActivityRpcTransaction>, ()> {
        let transaction = self
            .0
            .transaction_by_hash(rpc::TransactionHash::new(transaction_hash))
            .map_err(|_| ())?;
        let Some(transaction) = transaction else {
            return Ok(None);
        };
        let transaction = ActivityRpcTransaction {
            hash: *transaction.hash.as_bytes(),
            from: *transaction.from.as_bytes(),
            to: *transaction.to.as_bytes(),
            nonce: Word::from_be_bytes(*transaction.nonce.as_be_bytes()),
            value: Word::from_be_bytes(*transaction.value.as_be_bytes()),
            input: transaction.input.as_bytes().to_vec(),
            gas_limit: Word::from_be_bytes(*transaction.gas.as_be_bytes()),
            priority_fee: Word::from_be_bytes(*transaction.max_priority_fee_per_gas.as_be_bytes()),
            maximum_fee: Word::from_be_bytes(*transaction.max_fee_per_gas.as_be_bytes()),
            y_parity: transaction.y_parity,
            r: Word::from_be_bytes(*transaction.r.as_be_bytes()),
            s: Word::from_be_bytes(*transaction.s.as_be_bytes()),
            block: transaction.block.map(|block| ActivityRpcBlock {
                number: block.number,
                hash: *block.hash.as_bytes(),
            }),
            transaction_index: transaction.transaction_index,
        };
        canonical_observed_type_two_bytes(&transaction).map_err(|_| ())?;
        Ok(Some(transaction))
    }

    fn activity_receipt(
        &self,
        transaction_hash: [u8; 32],
    ) -> Result<Option<ActivityRpcReceipt>, ()> {
        self.0
            .transaction_receipt(rpc::TransactionHash::new(transaction_hash))
            .map(|receipt| {
                receipt.map(|receipt| ActivityRpcReceipt {
                    transaction_hash: *receipt.transaction_hash.as_bytes(),
                    from: *receipt.from.as_bytes(),
                    to: *receipt.to.as_bytes(),
                    outcome: match receipt.status {
                        rpc::TransactionStatus::Succeeded => InclusionOutcome::Success,
                        rpc::TransactionStatus::Failed => InclusionOutcome::Revert,
                    },
                    block: ActivityRpcBlock {
                        number: receipt.block.number,
                        hash: *receipt.block.hash.as_bytes(),
                    },
                    transaction_index: receipt.transaction_index,
                })
            })
            .map_err(|_| ())
    }

    fn activity_block(&self, number: u64) -> Result<Option<ActivityRpcBlock>, ()> {
        self.0
            .block_header_by_number(number)
            .map(|block| {
                block.map(|block| ActivityRpcBlock {
                    number: block.number,
                    hash: *block.hash.as_bytes(),
                })
            })
            .map_err(|_| ())
    }

    fn activity_head(&self) -> Result<ActivityRpcBlock, ()> {
        self.0
            .latest_block_header()
            .map(|block| ActivityRpcBlock {
                number: block.number,
                hash: *block.hash.as_bytes(),
            })
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

    fn send_raw_transaction(
        &self,
        signed: &[u8],
        permit: &SessionPermit<'_>,
    ) -> Result<[u8; 32], SendRawError> {
        self.0
            .send_raw_transaction(signed, permit)
            .map(|hash| *hash.as_bytes())
            .map_err(|error| match error {
                rpc::RpcError::SessionRevoked => SendRawError::SessionRevoked,
                _ => SendRawError::BroadcastUnknown,
            })
    }

    fn contract_code(&self, contract: [u8; 20]) -> Result<Vec<u8>, ()> {
        self.0
            .contract_code(rpc::Address20::new(contract))
            .map(|code| code.as_bytes().to_vec())
            .map_err(|_| ())
    }

    fn erc20_decimals(&self, contract: [u8; 20]) -> Result<Vec<u8>, ()> {
        self.0
            .erc20_decimals(rpc::Address20::new(contract))
            .map(|result| result.as_bytes().to_vec())
            .map_err(|_| ())
    }

    fn erc20_symbol(&self, contract: [u8; 20]) -> Result<Vec<u8>, ()> {
        self.0
            .erc20_symbol(rpc::Address20::new(contract))
            .map(|result| result.as_bytes().to_vec())
            .map_err(|_| ())
    }

    fn erc20_balance_of(&self, contract: [u8; 20], owner: [u8; 20]) -> Result<Vec<u8>, ()> {
        self.0
            .erc20_balance_of(rpc::Address20::new(contract), rpc::Address20::new(owner))
            .map(|result| result.as_bytes().to_vec())
            .map_err(|_| ())
    }

    fn erc20_transfer_preflight(
        &self,
        sender: [u8; 20],
        contract: [u8; 20],
        recipient: [u8; 20],
        amount: TokenAmount,
        nonce: Word,
        gas_limit: Word,
        priority_fee: Word,
        maximum_fee: Word,
    ) -> Result<Vec<u8>, ()> {
        self.0
            .erc20_transfer_preflight(
                rpc::Address20::new(sender),
                rpc::Address20::new(contract),
                rpc::Address20::new(recipient),
                amount,
                rpc::Quantity256::from_be_bytes(*nonce.as_be_bytes()),
                rpc::Quantity256::from_be_bytes(*gas_limit.as_be_bytes()),
                rpc::Quantity256::from_be_bytes(*priority_fee.as_be_bytes()),
                rpc::Quantity256::from_be_bytes(*maximum_fee.as_be_bytes()),
            )
            .map(|result| result.as_bytes().to_vec())
            .map_err(|_| ())
    }

    fn estimate_erc20_transfer_gas(
        &self,
        sender: [u8; 20],
        contract: [u8; 20],
        recipient: [u8; 20],
        amount: TokenAmount,
        nonce: Word,
        priority_fee: Word,
        maximum_fee: Word,
    ) -> Result<Word, ()> {
        self.0
            .estimate_erc20_transfer_gas(
                rpc::Address20::new(sender),
                rpc::Address20::new(contract),
                rpc::Address20::new(recipient),
                amount,
                rpc::Quantity256::from_be_bytes(*nonce.as_be_bytes()),
                rpc::Quantity256::from_be_bytes(*priority_fee.as_be_bytes()),
                rpc::Quantity256::from_be_bytes(*maximum_fee.as_be_bytes()),
            )
            .map(|value| Word::from_be_bytes(*value.as_be_bytes()))
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

    fn to_u64(self) -> Option<u64> {
        if self.0[..24].iter().any(|byte| *byte != 0) {
            return None;
        }
        Some(u64::from_be_bytes(self.0[24..].try_into().ok()?))
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

#[derive(Clone, Copy, Eq, PartialEq)]
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
    BackupConfirmationFailed,
    MigrationCleanup,
    MnemonicUnavailable,
    RandomnessUnavailable,
    CryptographicFailure,
    Locked,
    UnsupportedAccount,
    AccountSwitchBlocked,
    RpcUnavailable,
    BalanceUnavailable,
    TokenRequiresV2,
    TokenContractAddressInvalid,
    TokenContractEmpty,
    TokenQueryUnavailable,
    TokenMetadataInvalid,
    TokenCodeChanged,
    TokenMetadataChanged,
    TokenTransferRejected,
    TokenGasEstimateInvalid,
    InsufficientTokenBalance,
    TokenDuplicate,
    TokenCapacity,
    TokenNotFound,
    TokenStoreInvalid,
    TokenStoreStorage,
    TokenStoreChanged,
    TokenMutationBlocked,
    ActivityRequiresV2,
    ActivityCapacity,
    ActivityStoreInvalid,
    ActivityStoreStorage,
    ActivityStoreChanged,
    ActivityMutationBlocked,
    ActivityIdentityMismatch,
    ActivityNonceConflict,
    ActivityObservationInvalid,
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
    PendingAccountMismatch,
    PendingChanged,
    PendingCleanup,
    NoPreparedPending,
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
            Self::BackupConfirmationFailed => "BackendError::BackupConfirmationFailed",
            Self::MigrationCleanup => "BackendError::MigrationCleanup",
            Self::MnemonicUnavailable => "BackendError::MnemonicUnavailable",
            Self::RandomnessUnavailable => "BackendError::RandomnessUnavailable",
            Self::CryptographicFailure => "BackendError::CryptographicFailure",
            Self::Locked => "BackendError::Locked",
            Self::UnsupportedAccount => "BackendError::UnsupportedAccount",
            Self::AccountSwitchBlocked => "BackendError::AccountSwitchBlocked",
            Self::RpcUnavailable => "BackendError::RpcUnavailable",
            Self::BalanceUnavailable => "BackendError::BalanceUnavailable",
            Self::TokenRequiresV2 => "BackendError::TokenRequiresV2",
            Self::TokenContractAddressInvalid => "BackendError::TokenContractAddressInvalid",
            Self::TokenContractEmpty => "BackendError::TokenContractEmpty",
            Self::TokenQueryUnavailable => "BackendError::TokenQueryUnavailable",
            Self::TokenMetadataInvalid => "BackendError::TokenMetadataInvalid",
            Self::TokenCodeChanged => "BackendError::TokenCodeChanged",
            Self::TokenMetadataChanged => "BackendError::TokenMetadataChanged",
            Self::TokenTransferRejected => "BackendError::TokenTransferRejected",
            Self::TokenGasEstimateInvalid => "BackendError::TokenGasEstimateInvalid",
            Self::InsufficientTokenBalance => "BackendError::InsufficientTokenBalance",
            Self::TokenDuplicate => "BackendError::TokenDuplicate",
            Self::TokenCapacity => "BackendError::TokenCapacity",
            Self::TokenNotFound => "BackendError::TokenNotFound",
            Self::TokenStoreInvalid => "BackendError::TokenStoreInvalid",
            Self::TokenStoreStorage => "BackendError::TokenStoreStorage",
            Self::TokenStoreChanged => "BackendError::TokenStoreChanged",
            Self::TokenMutationBlocked => "BackendError::TokenMutationBlocked",
            Self::ActivityRequiresV2 => "BackendError::ActivityRequiresV2",
            Self::ActivityCapacity => "BackendError::ActivityCapacity",
            Self::ActivityStoreInvalid => "BackendError::ActivityStoreInvalid",
            Self::ActivityStoreStorage => "BackendError::ActivityStoreStorage",
            Self::ActivityStoreChanged => "BackendError::ActivityStoreChanged",
            Self::ActivityMutationBlocked => "BackendError::ActivityMutationBlocked",
            Self::ActivityIdentityMismatch => "BackendError::ActivityIdentityMismatch",
            Self::ActivityNonceConflict => "BackendError::ActivityNonceConflict",
            Self::ActivityObservationInvalid => "BackendError::ActivityObservationInvalid",
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
            Self::PendingAccountMismatch => "BackendError::PendingAccountMismatch",
            Self::PendingChanged => "BackendError::PendingChanged",
            Self::PendingCleanup => "BackendError::PendingCleanup",
            Self::NoPreparedPending => "BackendError::NoPreparedPending",
            Self::NoPreparedTransfer => "BackendError::NoPreparedTransfer",
            Self::PreparedInvalid => "BackendError::PreparedInvalid",
        })
    }
}

fn ensure_session_current(permit: &SessionPermit<'_>) -> Result<(), BackendError> {
    permit
        .is_current()
        .then_some(())
        .ok_or(BackendError::Locked)
}

fn guarded_broadcast(
    rpc: &dyn RpcAccess,
    signed: &[u8],
    permit: &SessionPermit<'_>,
) -> Result<[u8; 32], BackendError> {
    match rpc.send_raw_transaction(signed, permit) {
        Ok(hash) => Ok(hash),
        Err(SendRawError::SessionRevoked) => Err(BackendError::Locked),
        Err(SendRawError::BroadcastUnknown) => Err(BackendError::BroadcastUnknown),
    }
}

fn ensure_optional_session_current(permit: Option<&SessionPermit<'_>>) -> Result<(), BackendError> {
    match permit {
        Some(permit) => ensure_session_current(permit),
        None => Ok(()),
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
        BackendError::BackupConfirmationFailed => {
            "백업 확인에 실패했습니다. 지갑은 저장되지 않았습니다.".to_owned()
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
        BackendError::UnsupportedAccount => "선택할 수 없는 계정입니다.".to_owned(),
        BackendError::AccountSwitchBlocked => {
            "준비한 전송을 취소한 뒤 계정을 바꿔 주세요.".to_owned()
        }
        BackendError::RpcUnavailable => "Sepolia 연결을 확인하지 못했습니다.".to_owned(),
        BackendError::BalanceUnavailable => "Sepolia 잔액을 확인하지 못했습니다.".to_owned(),
        BackendError::TokenRequiresV2 => {
            "커스텀 토큰은 v2 지갑에서만 사용할 수 있습니다. v1 지갑을 먼저 이전해 주세요."
                .to_owned()
        }
        BackendError::TokenContractAddressInvalid => {
            "토큰 컨트랙트 주소 형식이나 체크섬을 확인해 주세요.".to_owned()
        }
        BackendError::TokenContractEmpty => {
            "해당 Sepolia 주소에서 컨트랙트 코드를 찾지 못했습니다.".to_owned()
        }
        BackendError::TokenQueryUnavailable => {
            "토큰 컨트랙트 정보를 확인하지 못했습니다.".to_owned()
        }
        BackendError::TokenMetadataInvalid => {
            "토큰 컨트랙트의 표준 메타데이터 응답이 올바르지 않습니다.".to_owned()
        }
        BackendError::TokenCodeChanged => {
            "저장 후 토큰 컨트랙트 코드가 달라져 메타데이터와 잔액을 숨겼습니다.".to_owned()
        }
        BackendError::TokenMetadataChanged => {
            "저장 후 토큰 메타데이터가 달라져 메타데이터와 잔액을 숨겼습니다.".to_owned()
        }
        BackendError::TokenTransferRejected => {
            "토큰 컨트랙트가 정확한 transfer 사전 실행을 거부했습니다.".to_owned()
        }
        BackendError::TokenGasEstimateInvalid => {
            "토큰 전송 가스 추정값이 허용 범위를 벗어났습니다.".to_owned()
        }
        BackendError::InsufficientTokenBalance => {
            "보낼 토큰 잔액이 부족합니다.".to_owned()
        }
        BackendError::TokenDuplicate => "이미 추가한 토큰 컨트랙트입니다.".to_owned(),
        BackendError::TokenCapacity => {
            "커스텀 토큰은 최대 32개까지 추가할 수 있습니다.".to_owned()
        }
        BackendError::TokenNotFound => {
            "인증된 목록에서 해당 저장 토큰 컨트랙트를 찾지 못했습니다.".to_owned()
        }
        BackendError::TokenStoreInvalid => {
            "인증된 토큰 목록이 손상되었거나 현재 v2 지갑과 일치하지 않습니다.".to_owned()
        }
        BackendError::TokenStoreStorage => {
            "인증된 토큰 목록을 안전하게 저장하지 못했습니다.".to_owned()
        }
        BackendError::TokenStoreChanged => {
            "토큰 목록이 다른 작업에서 변경되었습니다. 새로고침한 뒤 다시 시도해 주세요."
                .to_owned()
        }
        BackendError::ActivityRequiresV2 => {
            "v1 지갑에서는 새 거래를 전송하거나 활동 기록을 갱신할 수 없습니다. 먼저 v1 지갑을 v2로 이전하세요. 기존 보류 거래는 이전 중 그대로 보존됩니다."
                .to_owned()
        }
        BackendError::ActivityCapacity => {
            "거래 활동 기록이 최대 64개로 가득 찼습니다. 자동 삭제나 nonce 재사용은 하지 않습니다."
                .to_owned()
        }
        BackendError::ActivityStoreInvalid => {
            "거래 활동 기록이 손상되었거나 현재 v2 지갑과 일치하지 않습니다.".to_owned()
        }
        BackendError::ActivityStoreStorage => {
            "거래 활동 기록을 안전하게 읽거나 저장하지 못했습니다. 보류 거래는 보존됩니다."
                .to_owned()
        }
        BackendError::ActivityStoreChanged => {
            "거래 활동 기록이 다른 작업에서 변경되었습니다. 보류 거래를 보존하고 다시 확인하세요."
                .to_owned()
        }
        BackendError::ActivityMutationBlocked => {
            "다른 거래 활동 작업이 진행 중입니다. 보류 거래를 보존하고 잠시 후 다시 시도하세요."
                .to_owned()
        }
        BackendError::ActivityIdentityMismatch => {
            "RPC 거래 정보가 내구 기록의 불변 거래 정보와 일치하지 않습니다.".to_owned()
        }
        BackendError::ActivityNonceConflict => {
            "이 계정의 nonce는 이미 저장된 거래가 소유합니다. 어떤 상태도 자동 교체나 nonce 재사용을 허용하지 않습니다."
                .to_owned()
        }
        BackendError::ActivityObservationInvalid => {
            "거래 상태 관찰이 일관되지 않아 기록을 변경하지 않았습니다.".to_owned()
        }
        BackendError::TokenMutationBlocked => {
            "다른 토큰 목록 작업이 끝나거나 준비된 전송을 취소한 뒤 다시 시도해 주세요."
                .to_owned()
        }
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
            "일반 ETH 전송은 가스 추정값이 정확히 21,000이어야 합니다.".to_owned()
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
        BackendError::PendingAccountMismatch => {
            "보류 거래의 서명 계정을 현재 지갑에서 확인하지 못했습니다.".to_owned()
        }
        BackendError::PendingChanged => {
            "확인한 뒤 보류 거래 기록이 달라졌습니다. 다시 확인해 주세요.".to_owned()
        }
        BackendError::PendingCleanup => {
            "거래는 확인됐지만 보류 기록을 정리하지 못했습니다.".to_owned()
        }
        BackendError::NoPreparedPending => {
            "보류 거래의 서명 계정을 먼저 확인해 주세요.".to_owned()
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
    if kind != SecretExportKind::Mnemonic {
        return Err(BackendError::WalletMetadataInvalid);
    }
    Ok(SecretReveal::new(SecretRevealKind::Mnemonic, text))
}

fn account_private_key_reveal(
    export: SecretExport,
    account_index: u8,
    account_address: [u8; 20],
) -> Result<SecretReveal, BackendError> {
    let (kind, text) = export.into_zeroizing_text();
    if kind != SecretExportKind::AccountPrivateKey || account_index > 1 {
        return Err(BackendError::WalletMetadataInvalid);
    }
    Ok(SecretReveal::new_account_private_key(
        account_index,
        Zeroizing::new(checksum_address(account_address)),
        text,
    ))
}

fn generated_backup_reveal(
    export: SecretExport,
    first_address: [u8; 20],
    expires_at: Instant,
) -> Result<GeneratedBackupReveal, BackendError> {
    let (kind, phrase) = export.into_zeroizing_text();
    if kind != SecretExportKind::Mnemonic {
        return Err(BackendError::MnemonicUnavailable);
    }
    Ok(GeneratedBackupReveal::new(
        phrase,
        Zeroizing::new(checksum_address(first_address)),
        expires_at,
    ))
}

fn random_backup_challenge_positions(
    word_count: u8,
) -> Result<[u8; GENERATED_BACKUP_CHALLENGE_WORDS], BackendError> {
    choose_backup_challenge_positions(word_count, |bytes| {
        getrandom::fill(bytes).map_err(|_| BackendError::RandomnessUnavailable)
    })
}

fn choose_backup_challenge_positions(
    word_count: u8,
    mut fill_random: impl FnMut(&mut [u8]) -> Result<(), BackendError>,
) -> Result<[u8; GENERATED_BACKUP_CHALLENGE_WORDS], BackendError> {
    if !matches!(word_count, 12 | 24) {
        return Err(BackendError::WalletMetadataInvalid);
    }
    let mut pool = [0_u8; 24];
    for (index, value) in pool.iter_mut().take(usize::from(word_count)).enumerate() {
        *value = u8::try_from(index).map_err(|_| BackendError::CryptographicFailure)?;
    }
    let mut positions = [0_u8; GENERATED_BACKUP_CHALLENGE_WORDS];
    for (selection, position) in positions.iter_mut().enumerate() {
        let remaining = word_count
            .checked_sub(u8::try_from(selection).map_err(|_| BackendError::CryptographicFailure)?)
            .ok_or(BackendError::CryptographicFailure)?;
        let offset = usize::from(random_below(remaining, &mut fill_random)?);
        pool.swap(selection, selection + offset);
        *position = pool[selection]
            .checked_add(1)
            .ok_or(BackendError::CryptographicFailure)?;
    }
    positions.sort_unstable();
    Ok(positions)
}

fn random_below(
    bound: u8,
    fill_random: &mut impl FnMut(&mut [u8]) -> Result<(), BackendError>,
) -> Result<u8, BackendError> {
    if bound == 0 {
        return Err(BackendError::CryptographicFailure);
    }
    let bound_u16 = u16::from(bound);
    let limit = 256_u16 - (256_u16 % bound_u16);
    for _ in 0..MAX_RANDOM_SAMPLES {
        let mut sample = [0_u8; 1];
        fill_random(&mut sample)?;
        if u16::from(sample[0]) < limit {
            return Ok(sample[0] % bound);
        }
    }
    Err(BackendError::RandomnessUnavailable)
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
        SecretError::BackupConfirmationFailed => BackendError::BackupConfirmationFailed,
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

const fn map_token_store_error(error: TokenStoreError) -> BackendError {
    match error {
        TokenStoreError::Full => BackendError::TokenCapacity,
        TokenStoreError::Duplicate => BackendError::TokenDuplicate,
        TokenStoreError::NotFound => BackendError::TokenNotFound,
        TokenStoreError::RandomnessUnavailable => BackendError::RandomnessUnavailable,
        TokenStoreError::AuthenticationFailed | TokenStoreError::InvalidRecord => {
            BackendError::TokenStoreInvalid
        }
        TokenStoreError::InvalidInput => BackendError::TokenMetadataInvalid,
        TokenStoreError::GenerationOverflow => BackendError::TokenStoreInvalid,
    }
}

const fn map_activity_store_error(error: ActivityStoreError) -> BackendError {
    match error {
        ActivityStoreError::Full => BackendError::ActivityCapacity,
        ActivityStoreError::IdentityConflict => BackendError::ActivityIdentityMismatch,
        ActivityStoreError::NonceConflict => BackendError::ActivityNonceConflict,
        ActivityStoreError::RandomnessUnavailable => BackendError::RandomnessUnavailable,
        ActivityStoreError::AuthenticationFailed | ActivityStoreError::InvalidRecord => {
            BackendError::ActivityStoreInvalid
        }
        ActivityStoreError::InvalidTransition | ActivityStoreError::ObservationLimit => {
            BackendError::ActivityObservationInvalid
        }
        ActivityStoreError::InvalidInput
        | ActivityStoreError::NotFound
        | ActivityStoreError::GenerationOverflow => BackendError::ActivityStoreInvalid,
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

fn read_token_store_file(path: &Path) -> Result<Option<Vec<u8>>, BackendError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(BackendError::TokenStoreStorage),
    };
    if !metadata.file_type().is_file() || metadata.len() == 0 {
        return Err(BackendError::TokenStoreInvalid);
    }
    let length = usize::try_from(metadata.len()).map_err(|_| BackendError::TokenStoreInvalid)?;
    if length > MAX_TOKEN_STORE_BYTES {
        return Err(BackendError::TokenStoreInvalid);
    }
    let file = open_token_store_for_read(path)?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| BackendError::TokenStoreStorage)?;
    if !opened_metadata.file_type().is_file()
        || usize::try_from(opened_metadata.len()).ok() != Some(length)
    {
        return Err(BackendError::TokenStoreInvalid);
    }
    let mut bytes = Vec::with_capacity(length);
    file.take((MAX_TOKEN_STORE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| BackendError::TokenStoreStorage)?;
    if bytes.len() != length {
        return Err(BackendError::TokenStoreInvalid);
    }
    Ok(Some(bytes))
}

fn verify_exact_token_store_readback(
    path: &Path,
    expected: &[u8],
) -> Result<Vec<u8>, BackendError> {
    let actual = read_token_store_file(path)
        .map_err(|_| BackendError::TokenStoreStorage)?
        .ok_or(BackendError::TokenStoreStorage)?;
    if actual.as_slice() != expected {
        return Err(BackendError::TokenStoreStorage);
    }
    Ok(actual)
}

#[cfg(windows)]
fn open_token_store_for_read(path: &Path) -> Result<File, BackendError> {
    use std::os::windows::ffi::OsStrExt;

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(BackendError::TokenStoreStorage);
    }
    wide.push(0);
    // SAFETY: the NUL-terminated path remains live for the call. Opening the
    // final component itself prevents a reparse-point swap from being followed,
    // and omitting write/delete sharing pins these exact bytes for the read.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_READ.0 | FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|_| BackendError::TokenStoreStorage)?;
    // SAFETY: transfer the one successful owned handle into `File` exactly once.
    let file = unsafe { File::from_raw_handle(handle.0 as RawHandle) };
    let metadata = file
        .metadata()
        .map_err(|_| BackendError::TokenStoreStorage)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(BackendError::TokenStoreInvalid);
    }
    Ok(file)
}

#[cfg(not(windows))]
fn open_token_store_for_read(path: &Path) -> Result<File, BackendError> {
    File::open(path).map_err(|_| BackendError::TokenStoreStorage)
}

fn write_atomic_token_store(path: &Path, bytes: &[u8]) -> Result<(), BackendError> {
    if bytes.is_empty() || bytes.len() > MAX_TOKEN_STORE_BYTES {
        return Err(BackendError::TokenStoreInvalid);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(BackendError::TokenStoreInvalid);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(BackendError::TokenStoreStorage),
    }

    let parent = path.parent().ok_or(BackendError::TokenStoreStorage)?;
    let parent_directory =
        DurableParentDirectory::open(parent).map_err(|_| BackendError::TokenStoreStorage)?;
    let temporary = token_store_temporary_path(path)?;
    if path_may_exist(&temporary) {
        return Err(BackendError::TokenStoreStorage);
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|_| BackendError::TokenStoreStorage)?;
    let write_result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| BackendError::TokenStoreStorage);
    drop(file);
    if let Err(error) = write_result {
        if fs::remove_file(&temporary).is_ok() {
            let _ = parent_directory.flush();
        }
        return Err(error);
    }
    if let Err(error) = verify_exact_token_store_readback(&temporary, bytes) {
        if fs::remove_file(&temporary).is_ok() {
            let _ = parent_directory.flush();
        }
        return Err(error);
    }
    if let Err(error) = atomic_replace_token_store(&temporary, path) {
        if fs::remove_file(&temporary).is_ok() {
            let _ = parent_directory.flush();
        }
        return Err(error);
    }
    parent_directory
        .flush()
        .map_err(|_| BackendError::TokenStoreStorage)
}

fn token_store_temporary_path(path: &Path) -> Result<PathBuf, BackendError> {
    if path.file_name().is_none() {
        return Err(BackendError::TokenStoreStorage);
    }
    Ok(path.with_file_name("tokens-v1.tmp"))
}

#[cfg(windows)]
fn reconcile_orphan_token_temporary(
    temporary: &Path,
    parent_directory: &DurableParentDirectory,
) -> Result<(), BackendError> {
    use std::os::windows::ffi::OsStrExt;

    match fs::symlink_metadata(temporary) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Ok(_) => {}
        Err(_) => return Err(BackendError::TokenStoreStorage),
    }
    let mut wide: Vec<u16> = temporary.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(BackendError::TokenStoreStorage);
    }
    wide.push(0);
    // SAFETY: open the reserved final component itself with DELETE access and
    // no sharing. The retained token mutation lock serializes cooperating
    // writers while this exact prior-crash object is inspected and removed.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0 | DELETE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|_| BackendError::TokenStoreStorage)?;
    // SAFETY: transfer the one successful owned handle exactly once.
    let file = unsafe { File::from_raw_handle(handle.0 as RawHandle) };
    let metadata = file
        .metadata()
        .map_err(|_| BackendError::TokenStoreStorage)?;
    if !metadata.file_type().is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
    {
        return Err(BackendError::TokenStoreInvalid);
    }
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: `file` is the exact DELETE-capable no-share handle and the
    // disposition buffer remains live for the duration of the call.
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileDispositionInfo,
            std::ptr::from_ref(&disposition).cast(),
            u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO>())
                .map_err(|_| BackendError::TokenStoreStorage)?,
        )
    }
    .map_err(|_| BackendError::TokenStoreStorage)?;
    drop(file);
    parent_directory
        .flush()
        .map_err(|_| BackendError::TokenStoreStorage)?;
    match fs::symlink_metadata(temporary) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(BackendError::TokenStoreStorage),
    }
}

#[cfg(not(windows))]
fn reconcile_orphan_token_temporary(
    temporary: &Path,
    parent_directory: &DurableParentDirectory,
) -> Result<(), BackendError> {
    let metadata = match fs::symlink_metadata(temporary) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Ok(metadata) => metadata,
        Err(_) => return Err(BackendError::TokenStoreStorage),
    };
    if !metadata.file_type().is_file() {
        return Err(BackendError::TokenStoreInvalid);
    }
    fs::remove_file(temporary).map_err(|_| BackendError::TokenStoreStorage)?;
    parent_directory
        .flush()
        .map_err(|_| BackendError::TokenStoreStorage)
}

fn token_store_lock_path(path: &Path) -> Result<PathBuf, BackendError> {
    if path.file_name().is_none() {
        return Err(BackendError::TokenStoreStorage);
    }
    Ok(path.with_file_name("tokens-v1.lock"))
}

#[cfg(windows)]
fn atomic_replace_token_store(temporary: &Path, target: &Path) -> Result<(), BackendError> {
    use std::os::windows::ffi::OsStrExt;

    fn wide(path: &Path) -> Result<Vec<u16>, BackendError> {
        let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err(BackendError::TokenStoreStorage);
        }
        value.push(0);
        Ok(value)
    }

    let temporary = wide(temporary)?;
    let target = wide(target)?;
    // SAFETY: both NUL-terminated paths remain live for this call and are
    // sibling names beneath the already-held, non-reparse parent directory.
    unsafe {
        MoveFileExW(
            PCWSTR(temporary.as_ptr()),
            PCWSTR(target.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(|_| BackendError::TokenStoreStorage)
}

#[cfg(not(windows))]
fn atomic_replace_token_store(temporary: &Path, target: &Path) -> Result<(), BackendError> {
    fs::rename(temporary, target).map_err(|_| BackendError::TokenStoreStorage)
}

fn read_activity_store_file(path: &Path) -> Result<Option<Vec<u8>>, BackendError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(BackendError::ActivityStoreStorage),
    };
    if !metadata.file_type().is_file() || metadata.len() != ACTIVITY_FILE_BYTES as u64 {
        return Err(BackendError::ActivityStoreInvalid);
    }
    #[cfg(windows)]
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(BackendError::ActivityStoreInvalid);
    }
    let file = open_activity_store_for_read(path)?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| BackendError::ActivityStoreStorage)?;
    if !opened_metadata.file_type().is_file() || opened_metadata.len() != ACTIVITY_FILE_BYTES as u64
    {
        return Err(BackendError::ActivityStoreInvalid);
    }
    let mut bytes = Vec::with_capacity(ACTIVITY_FILE_BYTES);
    file.take((ACTIVITY_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| BackendError::ActivityStoreStorage)?;
    if bytes.len() != ACTIVITY_FILE_BYTES {
        return Err(BackendError::ActivityStoreInvalid);
    }
    Ok(Some(bytes))
}

fn verify_exact_activity_store_readback(
    path: &Path,
    expected: &[u8],
) -> Result<Vec<u8>, BackendError> {
    let actual = read_activity_store_file(path)?.ok_or(BackendError::ActivityStoreStorage)?;
    if actual.as_slice() != expected {
        return Err(BackendError::ActivityStoreStorage);
    }
    Ok(actual)
}

#[cfg(windows)]
fn open_activity_store_for_read(path: &Path) -> Result<File, BackendError> {
    use std::os::windows::ffi::OsStrExt;

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(BackendError::ActivityStoreStorage);
    }
    wide.push(0);
    // SAFETY: the NUL-terminated final-component path remains live. Opening
    // the reparse point itself and omitting write/delete sharing pins these
    // exact bytes while they are authenticated.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_READ.0 | FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|_| BackendError::ActivityStoreStorage)?;
    // SAFETY: transfer the one successful owned handle into `File` once.
    let file = unsafe { File::from_raw_handle(handle.0 as RawHandle) };
    let metadata = file
        .metadata()
        .map_err(|_| BackendError::ActivityStoreStorage)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(BackendError::ActivityStoreInvalid);
    }
    Ok(file)
}

#[cfg(not(windows))]
fn open_activity_store_for_read(path: &Path) -> Result<File, BackendError> {
    File::open(path).map_err(|_| BackendError::ActivityStoreStorage)
}

fn write_atomic_activity_store(
    activity_lease: &ActivityMutationLease<'_>,
    path: &Path,
    bytes: &[u8],
) -> Result<(), BackendError> {
    if activity_lease.activity_store_path != path {
        return Err(BackendError::ActivityMutationBlocked);
    }
    if bytes.len() != ACTIVITY_FILE_BYTES {
        return Err(BackendError::ActivityStoreInvalid);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(BackendError::ActivityStoreInvalid);
        }
        #[cfg(windows)]
        Ok(metadata) if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 => {
            return Err(BackendError::ActivityStoreInvalid);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(BackendError::ActivityStoreStorage),
    }
    let parent = path.parent().ok_or(BackendError::ActivityStoreStorage)?;
    let parent_directory =
        DurableParentDirectory::open(parent).map_err(|_| BackendError::ActivityStoreStorage)?;
    let temporary = activity_store_temporary_path(path)?;
    if path_may_exist(&temporary) {
        return Err(BackendError::ActivityStoreStorage);
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|_| BackendError::ActivityStoreStorage)?;
    let write_result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| BackendError::ActivityStoreStorage);
    drop(file);
    if let Err(error) = write_result {
        if fs::remove_file(&temporary).is_ok() {
            let _ = parent_directory.flush();
        }
        return Err(error);
    }
    if let Err(error) = verify_exact_activity_store_readback(&temporary, bytes) {
        if fs::remove_file(&temporary).is_ok() {
            let _ = parent_directory.flush();
        }
        return Err(error);
    }
    if let Err(error) = atomic_replace_activity_store(&temporary, path) {
        if fs::remove_file(&temporary).is_ok() {
            let _ = parent_directory.flush();
        }
        return Err(error);
    }
    parent_directory
        .flush()
        .map_err(|_| BackendError::ActivityStoreStorage)
}

#[cfg(windows)]
fn reconcile_orphan_activity_temporary(
    temporary: &Path,
    parent_directory: &DurableParentDirectory,
) -> Result<(), BackendError> {
    use std::os::windows::ffi::OsStrExt;

    match fs::symlink_metadata(temporary) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Ok(_) => {}
        Err(_) => return Err(BackendError::ActivityStoreStorage),
    }
    let mut wide: Vec<u16> = temporary.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(BackendError::ActivityStoreStorage);
    }
    wide.push(0);
    // SAFETY: this reserved sibling name is opened as the final component.
    // Zero sharing pins the exact prior-crash object; DELETE access permits
    // handle cleanup without a close/path-delete substitution window.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0 | DELETE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|_| BackendError::ActivityStoreStorage)?;
    // SAFETY: transfer the one successful owned handle into `File` once.
    let file = unsafe { File::from_raw_handle(handle.0 as RawHandle) };
    let metadata = file
        .metadata()
        .map_err(|_| BackendError::ActivityStoreStorage)?;
    if !metadata.file_type().is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
    {
        return Err(BackendError::ActivityStoreInvalid);
    }
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: `file` is the exact DELETE-capable no-share handle and the
    // disposition buffer remains live for the call.
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileDispositionInfo,
            std::ptr::from_ref(&disposition).cast(),
            u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO>())
                .map_err(|_| BackendError::ActivityStoreStorage)?,
        )
    }
    .map_err(|_| BackendError::ActivityStoreStorage)?;
    drop(file);
    parent_directory
        .flush()
        .map_err(|_| BackendError::ActivityStoreStorage)?;
    match fs::symlink_metadata(temporary) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(BackendError::ActivityStoreStorage),
    }
}

#[cfg(not(windows))]
fn reconcile_orphan_activity_temporary(
    temporary: &Path,
    parent_directory: &DurableParentDirectory,
) -> Result<(), BackendError> {
    // Development/test compatibility only. Production Windows exact-object
    // cleanup is protected by ActivityMutationLease and the no-share handle.
    let metadata = match fs::symlink_metadata(temporary) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Ok(metadata) => metadata,
        Err(_) => return Err(BackendError::ActivityStoreStorage),
    };
    if !metadata.file_type().is_file() {
        return Err(BackendError::ActivityStoreInvalid);
    }
    fs::remove_file(temporary).map_err(|_| BackendError::ActivityStoreStorage)?;
    parent_directory
        .flush()
        .map_err(|_| BackendError::ActivityStoreStorage)
}

#[cfg(windows)]
fn atomic_replace_activity_store(temporary: &Path, target: &Path) -> Result<(), BackendError> {
    use std::os::windows::ffi::OsStrExt;

    fn wide(path: &Path) -> Result<Vec<u16>, BackendError> {
        let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err(BackendError::ActivityStoreStorage);
        }
        value.push(0);
        Ok(value)
    }
    let temporary = wide(temporary)?;
    let target = wide(target)?;
    // SAFETY: both NUL-terminated sibling paths stay live for the call; the
    // outer activity lease retains the verified parent and lock handles.
    unsafe {
        MoveFileExW(
            PCWSTR(temporary.as_ptr()),
            PCWSTR(target.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(|_| BackendError::ActivityStoreStorage)
}

#[cfg(not(windows))]
fn atomic_replace_activity_store(temporary: &Path, target: &Path) -> Result<(), BackendError> {
    fs::rename(temporary, target).map_err(|_| BackendError::ActivityStoreStorage)
}

/// Pins the authenticated legacy vault and its parent across the whole v1→v2
/// commit. On Windows the exact regular file is opened with DELETE access and
/// no sharing, so the final cleanup can mark that handle delete-pending rather
/// than deleting whatever happens to occupy the path later.
struct LegacyVaultMigrationLease {
    file: Option<File>,
    parent_directory: DurableParentDirectory,
    #[cfg(not(windows))]
    _process_guard: MutexGuard<'static, ()>,
}

impl LegacyVaultMigrationLease {
    #[cfg(windows)]
    fn open(path: &Path) -> Result<Self, BackendError> {
        use std::os::windows::ffi::OsStrExt;

        let parent = path.parent().ok_or(BackendError::StorageUnavailable)?;
        let parent_directory = DurableParentDirectory::open(parent)?;
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err(BackendError::VaultInvalid);
        }
        wide.push(0);
        // SAFETY: `wide` is NUL terminated and remains live. DELETE access and
        // zero sharing pin this exact object through authenticated read, v2
        // creation/readback, handle deletion, and in-memory activation.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                FILE_READ_DATA.0 | FILE_READ_ATTRIBUTES.0 | DELETE.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .map_err(|_| BackendError::StorageUnavailable)?;
        // SAFETY: transfer the one successful owned handle into `File` once.
        let file = unsafe { File::from_raw_handle(handle.0 as RawHandle) };
        let metadata = file
            .metadata()
            .map_err(|_| BackendError::StorageUnavailable)?;
        if !metadata.file_type().is_file()
            || metadata.len() != VAULT_FILE_BYTES as u64
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        {
            return Err(BackendError::VaultInvalid);
        }
        Ok(Self {
            file: Some(file),
            parent_directory,
        })
    }

    #[cfg(not(windows))]
    fn open(path: &Path) -> Result<Self, BackendError> {
        // Development/test compatibility only. The supported Windows path
        // proves cross-process exact-object pinning; this guard serializes only
        // cooperating operations in the current process.
        let process_guard = LEGACY_MIGRATION_PROCESS_LOCK
            .lock()
            .map_err(|_| BackendError::StorageUnavailable)?;
        let parent = path.parent().ok_or(BackendError::StorageUnavailable)?;
        let parent_directory = DurableParentDirectory::open(parent)?;
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                BackendError::LegacyNotFound
            } else {
                BackendError::StorageUnavailable
            }
        })?;
        if !metadata.file_type().is_file() || metadata.len() != VAULT_FILE_BYTES as u64 {
            return Err(BackendError::VaultInvalid);
        }
        let file = File::open(path).map_err(|_| BackendError::StorageUnavailable)?;
        Ok(Self {
            file: Some(file),
            parent_directory,
            _process_guard: process_guard,
        })
    }

    fn read_exact(&mut self) -> Result<Zeroizing<Vec<u8>>, BackendError> {
        let file = self.file.as_mut().ok_or(BackendError::MigrationCleanup)?;
        let metadata = file
            .metadata()
            .map_err(|_| BackendError::StorageUnavailable)?;
        if !metadata.file_type().is_file() || metadata.len() != VAULT_FILE_BYTES as u64 {
            return Err(BackendError::VaultInvalid);
        }
        #[cfg(windows)]
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            return Err(BackendError::VaultInvalid);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| BackendError::StorageUnavailable)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(VAULT_FILE_BYTES));
        (&mut *file)
            .take((VAULT_FILE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| BackendError::StorageUnavailable)?;
        if bytes.len() != VAULT_FILE_BYTES {
            return Err(BackendError::VaultInvalid);
        }
        Ok(bytes)
    }

    #[cfg(windows)]
    fn delete_exact(&mut self, path: &Path) -> Result<(), BackendError> {
        let file = self.file.as_ref().ok_or(BackendError::MigrationCleanup)?;
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: `disposition` has the documented layout and the live handle
        // is the same DELETE-capable no-share object authenticated above.
        unsafe {
            SetFileInformationByHandle(
                HANDLE(file.as_raw_handle()),
                FileDispositionInfo,
                std::ptr::from_ref(&disposition).cast(),
                u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO>())
                    .map_err(|_| BackendError::MigrationCleanup)?,
            )
        }
        .map_err(|_| BackendError::MigrationCleanup)?;
        drop(self.file.take());
        self.parent_directory
            .flush()
            .map_err(|_| BackendError::MigrationCleanup)?;
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(_) | Err(_) => Err(BackendError::MigrationCleanup),
        }
    }

    #[cfg(not(windows))]
    fn delete_exact(&mut self, path: &Path) -> Result<(), BackendError> {
        // Development/test compatibility only; the process guard does not
        // exclude an uncooperative same-user process from a path replacement.
        fs::remove_file(path).map_err(|_| BackendError::MigrationCleanup)?;
        drop(self.file.take());
        self.parent_directory
            .flush()
            .map_err(|_| BackendError::MigrationCleanup)
    }
}

#[cfg(windows)]
fn reconcile_orphan_v2_migration_temporary(
    temporary: &Path,
    parent_directory: &DurableParentDirectory,
) -> Result<(), BackendError> {
    use std::os::windows::ffi::OsStrExt;

    match fs::symlink_metadata(temporary) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Ok(_) => {}
        Err(_) => return Err(BackendError::StorageUnavailable),
    }
    let mut wide: Vec<u16> = temporary.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(BackendError::StorageUnavailable);
    }
    wide.push(0);
    // SAFETY: the reserved migrating name is opened as the final component;
    // zero sharing pins exactly one prior-crash object for verified cleanup.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0 | DELETE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|_| BackendError::StorageUnavailable)?;
    // SAFETY: transfer the returned owned handle into `File` once.
    let file = unsafe { File::from_raw_handle(handle.0 as RawHandle) };
    let metadata = file
        .metadata()
        .map_err(|_| BackendError::StorageUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
    {
        return Err(BackendError::VaultInvalid);
    }
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: `file` is the exact DELETE-capable no-share object and the
    // disposition buffer remains live for the call.
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileDispositionInfo,
            std::ptr::from_ref(&disposition).cast(),
            u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO>())
                .map_err(|_| BackendError::MigrationCleanup)?,
        )
    }
    .map_err(|_| BackendError::MigrationCleanup)?;
    drop(file);
    parent_directory
        .flush()
        .map_err(|_| BackendError::MigrationCleanup)?;
    match fs::symlink_metadata(temporary) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(BackendError::MigrationCleanup),
    }
}

#[cfg(not(windows))]
fn reconcile_orphan_v2_migration_temporary(
    temporary: &Path,
    parent_directory: &DurableParentDirectory,
) -> Result<(), BackendError> {
    // Development/test compatibility only; the migration process mutex is
    // not cross-process exact-object evidence.
    let metadata = match fs::symlink_metadata(temporary) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Ok(metadata) => metadata,
        Err(_) => return Err(BackendError::StorageUnavailable),
    };
    if !metadata.file_type().is_file() {
        return Err(BackendError::VaultInvalid);
    }
    fs::remove_file(temporary).map_err(|_| BackendError::MigrationCleanup)?;
    parent_directory
        .flush()
        .map_err(|_| BackendError::MigrationCleanup)
}

/// Owns the exact newly created v2 object with no sharing through authenticated
/// readback, legacy handle deletion, and activation. This closes the symmetric
/// gap where a path-only readback could otherwise be replaced before v1 cleanup.
struct CreatedV2VaultMigrationLease {
    file: Option<File>,
    parent_directory: DurableParentDirectory,
    path: PathBuf,
    committed: bool,
}

impl CreatedV2VaultMigrationLease {
    fn create(path: &Path, bytes: &[u8]) -> Result<Self, BackendError> {
        if bytes.is_empty() || bytes.len() > MAX_V2_VAULT_BYTES {
            return Err(BackendError::VaultInvalid);
        }
        let parent = path.parent().ok_or(BackendError::StorageUnavailable)?;
        fs::create_dir_all(parent).map_err(|_| BackendError::StorageUnavailable)?;
        let parent_directory = DurableParentDirectory::open(parent)?;
        if path_may_exist(path) {
            return Err(BackendError::AlreadyExists);
        }
        let temporary = vault_v2_migration_temporary_path(path)?;
        reconcile_orphan_v2_migration_temporary(&temporary, &parent_directory)?;
        let mut options = OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;

            options
                .access_mode(GENERIC_READ.0 | GENERIC_WRITE.0 | FILE_READ_ATTRIBUTES.0 | DELETE.0)
                .share_mode(0)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
        }
        let file = match options.open(&temporary) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(BackendError::AlreadyExists);
            }
            Err(_) => return Err(BackendError::StorageUnavailable),
        };
        let mut lease = Self {
            file: Some(file),
            parent_directory,
            path: temporary,
            committed: false,
        };
        let initialize_result = (|| {
            let file = lease
                .file
                .as_mut()
                .ok_or(BackendError::StorageUnavailable)?;
            let metadata = file
                .metadata()
                .map_err(|_| BackendError::StorageUnavailable)?;
            if !metadata.file_type().is_file() {
                return Err(BackendError::VaultInvalid);
            }
            #[cfg(windows)]
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
                return Err(BackendError::VaultInvalid);
            }
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| BackendError::StorageUnavailable)?;
            lease.parent_directory.flush()?;
            lease.verify_exact(bytes)
        })();
        if let Err(error) = initialize_result {
            lease.abort()?;
            return Err(error);
        }
        Ok(lease)
    }

    fn read_exact(&mut self) -> Result<Zeroizing<Vec<u8>>, BackendError> {
        let file = self.file.as_mut().ok_or(BackendError::StorageUnavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| BackendError::StorageUnavailable)?;
        if !metadata.file_type().is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_V2_VAULT_BYTES as u64
        {
            return Err(BackendError::VaultInvalid);
        }
        #[cfg(windows)]
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            return Err(BackendError::VaultInvalid);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| BackendError::StorageUnavailable)?;
        let length = usize::try_from(metadata.len()).map_err(|_| BackendError::VaultInvalid)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(length));
        (&mut *file)
            .take((MAX_V2_VAULT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| BackendError::StorageUnavailable)?;
        if bytes.len() != length {
            return Err(BackendError::VaultInvalid);
        }
        Ok(bytes)
    }

    fn verify_exact(&mut self, expected: &[u8]) -> Result<(), BackendError> {
        let actual = self.read_exact()?;
        if actual.as_slice() == expected {
            Ok(())
        } else {
            Err(BackendError::WalletChanged)
        }
    }

    fn mark_committed(&mut self) -> Result<(), BackendError> {
        if self.file.is_none() || self.committed {
            return Err(BackendError::WalletChanged);
        }
        self.committed = true;
        Ok(())
    }

    #[cfg(windows)]
    fn install_exact(&mut self, target: &Path) -> Result<(), BackendError> {
        use std::os::windows::ffi::OsStrExt;

        if self.committed || path_may_exist(target) {
            return Err(BackendError::AlreadyExists);
        }
        let file = self.file.as_ref().ok_or(BackendError::StorageUnavailable)?;
        let wide: Vec<u16> = target.as_os_str().encode_wide().collect();
        if wide.is_empty() || wide.contains(&0) {
            return Err(BackendError::StorageUnavailable);
        }
        let name_bytes = wide
            .len()
            .checked_mul(std::mem::size_of::<u16>())
            .ok_or(BackendError::StorageUnavailable)?;
        let total_bytes = std::mem::size_of::<FILE_RENAME_INFO>()
            .checked_add(name_bytes)
            .ok_or(BackendError::StorageUnavailable)?;
        let word_bytes = std::mem::size_of::<u64>();
        let word_count = total_bytes
            .checked_add(word_bytes - 1)
            .ok_or(BackendError::StorageUnavailable)?
            / word_bytes;
        let mut storage = vec![0_u64; word_count];
        let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        // SAFETY: `storage` is u64-aligned and sized for the fixed header plus
        // the complete UTF-16 destination. The already-held parent prevents
        // directory replacement and the destination is the fixed sibling;
        // replacement is disabled.
        unsafe {
            (*info).Anonymous.ReplaceIfExists = false;
            (*info).RootDirectory = HANDLE::default();
            (*info).FileNameLength =
                u32::try_from(name_bytes).map_err(|_| BackendError::StorageUnavailable)?;
            std::ptr::copy_nonoverlapping(
                wide.as_ptr(),
                std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
                wide.len(),
            );
            SetFileInformationByHandle(
                HANDLE(file.as_raw_handle()),
                FileRenameInfo,
                info.cast(),
                u32::try_from(total_bytes).map_err(|_| BackendError::StorageUnavailable)?,
            )
        }
        .map_err(|_| BackendError::StorageUnavailable)?;
        self.parent_directory.flush()?;
        match fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) | Err(_) => return Err(BackendError::StorageUnavailable),
        }
        // Do not reopen the final path while our exact handle intentionally
        // denies sharing. Successful handle rename plus the now-absent temp
        // name binds this same already-validated regular object to `target`;
        // the caller immediately rereads/authenticates through this handle.
        self.path = target.to_path_buf();
        Ok(())
    }

    #[cfg(not(windows))]
    fn install_exact(&mut self, target: &Path) -> Result<(), BackendError> {
        // Development/test compatibility only; LegacyVaultMigrationLease's
        // process mutex serializes cooperating callers on this platform.
        if self.committed || path_may_exist(target) {
            return Err(BackendError::AlreadyExists);
        }
        fs::rename(&self.path, target).map_err(|_| BackendError::StorageUnavailable)?;
        self.parent_directory.flush()?;
        self.path = target.to_path_buf();
        Ok(())
    }

    #[cfg(windows)]
    fn abort(&mut self) -> Result<(), BackendError> {
        let Some(file) = self.file.as_ref() else {
            return Ok(());
        };
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: this is the exact create-new, DELETE-capable no-share handle
        // and `disposition` remains live for the call.
        unsafe {
            SetFileInformationByHandle(
                HANDLE(file.as_raw_handle()),
                FileDispositionInfo,
                std::ptr::from_ref(&disposition).cast(),
                u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO>())
                    .map_err(|_| BackendError::MigrationCleanup)?,
            )
        }
        .map_err(|_| BackendError::MigrationCleanup)?;
        drop(self.file.take());
        self.parent_directory
            .flush()
            .map_err(|_| BackendError::MigrationCleanup)?;
        match fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(_) | Err(_) => Err(BackendError::MigrationCleanup),
        }
    }

    #[cfg(not(windows))]
    fn abort(&mut self) -> Result<(), BackendError> {
        if self.file.is_none() {
            return Ok(());
        }
        fs::remove_file(&self.path).map_err(|_| BackendError::MigrationCleanup)?;
        drop(self.file.take());
        self.parent_directory
            .flush()
            .map_err(|_| BackendError::MigrationCleanup)
    }
}

impl Drop for CreatedV2VaultMigrationLease {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.abort();
        }
    }
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

/// Pins the exact pending file object from attribution through retry. On
/// Windows, denying every share mode prevents another process from reading,
/// modifying, renaming, or deleting the record while authorization is live.
struct PendingFileLease {
    file: File,
    #[cfg(not(windows))]
    _process_lease: PendingProcessLease,
}

#[cfg(not(windows))]
static PENDING_PROCESS_LEASED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(not(windows))]
struct PendingProcessLease;

#[cfg(not(windows))]
impl Drop for PendingProcessLease {
    fn drop(&mut self) {
        PENDING_PROCESS_LEASED.store(false, std::sync::atomic::Ordering::Release);
    }
}

impl PendingFileLease {
    #[cfg(windows)]
    fn open(path: &Path) -> Result<Self, BackendError> {
        use std::os::windows::ffi::OsStrExt;

        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err(BackendError::PendingInvalid);
        }
        wide.push(0);
        // SAFETY: `wide` is live and NUL terminated. DELETE access plus a zero
        // share mode pins this exact object and later permits handle-based
        // delete-pending without a close/reopen or path deletion gap.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                FILE_READ_DATA.0 | FILE_READ_ATTRIBUTES.0 | DELETE.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .map_err(|_| BackendError::PendingInvalid)?;
        // SAFETY: the returned handle is owned and transferred exactly once.
        let file = unsafe { File::from_raw_handle(handle.0 as RawHandle) };
        let metadata = file.metadata().map_err(|_| BackendError::PendingInvalid)?;
        if !metadata.file_type().is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        {
            return Err(BackendError::PendingInvalid);
        }
        Ok(Self { file })
    }

    #[cfg(not(windows))]
    fn open(path: &Path) -> Result<Self, BackendError> {
        // Development/test compatibility only. The supported Windows release
        // proves cross-process exact-object pinning with a zero-share handle;
        // this process-local fallback is not production evidence.
        PENDING_PROCESS_LEASED
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::Acquire,
                std::sync::atomic::Ordering::Relaxed,
            )
            .map_err(|_| BackendError::PendingChanged)?;
        let process_lease = PendingProcessLease;
        let metadata = fs::symlink_metadata(path).map_err(|_| BackendError::PendingInvalid)?;
        if !metadata.file_type().is_file() {
            return Err(BackendError::PendingInvalid);
        }
        let file = File::open(path).map_err(|_| BackendError::PendingInvalid)?;
        Ok(Self {
            file,
            _process_lease: process_lease,
        })
    }

    fn read_record(&mut self) -> Result<PendingRecord, BackendError> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| BackendError::PendingInvalid)?;
        read_pending_file(&mut self.file)
    }

    #[cfg(windows)]
    fn delete_exact(self, path: &Path) -> Result<(), BackendError> {
        let parent = path.parent().ok_or(BackendError::PendingCleanup)?;
        let parent_directory =
            DurableParentDirectory::open(parent).map_err(|_| BackendError::PendingCleanup)?;
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: `disposition` has the exact documented layout and remains
        // live for the call; `self.file` owns a live DELETE-capable handle.
        unsafe {
            SetFileInformationByHandle(
                HANDLE(self.file.as_raw_handle()),
                FileDispositionInfo,
                std::ptr::from_ref(&disposition).cast(),
                u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO>())
                    .map_err(|_| BackendError::PendingCleanup)?,
            )
        }
        .map_err(|_| BackendError::PendingCleanup)?;
        drop(self.file);
        parent_directory
            .flush()
            .map_err(|_| BackendError::PendingCleanup)?;
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(_) | Err(_) => Err(BackendError::PendingCleanup),
        }
    }

    #[cfg(not(windows))]
    fn delete_exact(self, path: &Path) -> Result<(), BackendError> {
        // Development/test compatibility only; see `open` above.
        let parent = path.parent().ok_or(BackendError::PendingCleanup)?;
        let parent_directory =
            DurableParentDirectory::open(parent).map_err(|_| BackendError::PendingCleanup)?;
        fs::remove_file(path).map_err(|_| BackendError::PendingCleanup)?;
        drop(self.file);
        parent_directory
            .flush()
            .map_err(|_| BackendError::PendingCleanup)
    }
}

struct PendingRecord {
    transaction_hash: [u8; 32],
    raw_transaction: Zeroizing<Vec<u8>>,
}

fn verify_pending_lease(
    lease: &mut PendingFileLease,
    expected_hash: [u8; 32],
    expected_raw: &[u8],
) -> Result<(), BackendError> {
    let record = lease.read_record()?;
    if record.transaction_hash == expected_hash && record.raw_transaction.as_slice() == expected_raw
    {
        Ok(())
    } else {
        Err(BackendError::PendingChanged)
    }
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

#[cfg(test)]
fn read_pending(path: &Path) -> Result<PendingRecord, BackendError> {
    let mut lease = PendingFileLease::open(path)?;
    lease.read_record()
}

#[cfg(test)]
fn remove_pending(path: &Path) -> Result<(), BackendError> {
    PendingFileLease::open(path)?.delete_exact(path)
}

fn read_pending_file(file: &mut File) -> Result<PendingRecord, BackendError> {
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

fn sibling_pending_path(vault_path: &Path) -> Result<PathBuf, String> {
    if vault_path.file_name().is_none() {
        return Err(error_text(BackendError::StorageUnavailable));
    }
    Ok(vault_path.with_file_name("pending-v1.bin"))
}

fn sibling_token_store_path(vault_v2_path: &Path) -> Result<PathBuf, String> {
    if vault_v2_path.file_name().is_none() {
        return Err(error_text(BackendError::TokenStoreStorage));
    }
    Ok(vault_v2_path.with_file_name("tokens-v1.bin"))
}

fn sibling_activity_store_path(vault_v2_path: &Path) -> Result<PathBuf, String> {
    if vault_v2_path.file_name().is_none() {
        return Err(error_text(BackendError::ActivityStoreStorage));
    }
    Ok(vault_v2_path.with_file_name("activity-v1.bin"))
}

fn vault_v2_migration_temporary_path(path: &Path) -> Result<PathBuf, BackendError> {
    if path.file_name().is_none() {
        return Err(BackendError::StorageUnavailable);
    }
    Ok(path.with_file_name("vault-v2.migrating"))
}

fn activity_store_temporary_path(path: &Path) -> Result<PathBuf, BackendError> {
    if path.file_name().is_none() {
        return Err(BackendError::ActivityStoreStorage);
    }
    Ok(path.with_file_name("activity-v1.tmp"))
}

fn activity_store_lock_path(path: &Path) -> Result<PathBuf, BackendError> {
    if path.file_name().is_none() {
        return Err(BackendError::ActivityStoreStorage);
    }
    Ok(path.with_file_name("activity-v1.lock"))
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

fn parse_transaction_hash(value: &str) -> Result<[u8; 32], BackendError> {
    let hex = value
        .strip_prefix("0x")
        .ok_or(BackendError::ActivityIdentityMismatch)?;
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BackendError::ActivityIdentityMismatch);
    }
    let mut output = [0_u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    if output == [0; 32] {
        return Err(BackendError::ActivityIdentityMismatch);
    }
    Ok(output)
}

fn activity_transaction_matches_identity(
    transaction: &ActivityRpcTransaction,
    identity: &TransactionIdentity,
) -> bool {
    if transaction.hash != *identity.transaction_hash()
        || transaction.from != *identity.sender()
        || transaction.nonce != Word::from_be_bytes(*identity.nonce())
        || transaction.gas_limit != Word::from_be_bytes(*identity.gas_limit())
        || transaction.priority_fee != Word::from_be_bytes(*identity.max_priority_fee_per_gas())
        || transaction.maximum_fee != Word::from_be_bytes(*identity.max_fee_per_gas())
    {
        return false;
    }
    match identity.transfer() {
        Transfer::Native { .. } => {
            transaction.to == *identity.transfer().recipient()
                && identity
                    .transfer()
                    .native_value()
                    .is_some_and(|value| transaction.value == Word::from_be_bytes(*value))
                && transaction.input.is_empty()
        }
        Transfer::SavedErc20 { .. } => {
            let Some(contract) = identity.transfer().contract() else {
                return false;
            };
            let Some(raw_amount) = identity.transfer().raw_amount() else {
                return false;
            };
            let expected = erc20::transfer_call_data(
                *identity.transfer().recipient(),
                TokenAmount::from_be_bytes(*raw_amount),
            );
            transaction.to == *contract
                && transaction.value.is_zero()
                && transaction.input.as_slice() == expected
        }
    }
}

fn activity_receipt_matches_identity(
    receipt: &ActivityRpcReceipt,
    identity: &TransactionIdentity,
) -> bool {
    let expected_to = identity
        .transfer()
        .contract()
        .unwrap_or_else(|| identity.transfer().recipient());
    receipt.transaction_hash == *identity.transaction_hash()
        && receipt.from == *identity.sender()
        && receipt.to == *expected_to
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

fn activity_snapshot_from_entry(
    entry: &ActivityEntry,
) -> Result<TransactionActivitySnapshot, BackendError> {
    let identity = entry.identity();
    let transfer = match identity.transfer() {
        Transfer::Native { .. } => ActivityTransferSnapshot::Native {
            recipient_address: checksum_address(*identity.transfer().recipient()),
            value_eth: format_ether(Word::from_be_bytes(
                *identity
                    .transfer()
                    .native_value()
                    .ok_or(BackendError::ActivityStoreInvalid)?,
            )),
        },
        Transfer::SavedErc20 { .. } => {
            let raw_amount = *identity
                .transfer()
                .raw_amount()
                .ok_or(BackendError::ActivityStoreInvalid)?;
            let decimals = identity
                .transfer()
                .decimals()
                .ok_or(BackendError::ActivityStoreInvalid)?;
            ActivityTransferSnapshot::SavedErc20 {
                contract_address: checksum_address(
                    *identity
                        .transfer()
                        .contract()
                        .ok_or(BackendError::ActivityStoreInvalid)?,
                ),
                recipient_address: checksum_address(*identity.transfer().recipient()),
                raw_amount: decimal_string(Word::from_be_bytes(raw_amount)),
                decimals,
                amount: erc20::format_token_amount(
                    TokenAmount::from_be_bytes(raw_amount),
                    decimals,
                )
                .map_err(|_| BackendError::ActivityStoreInvalid)?,
                historical_symbol: identity.transfer().symbol().map(str::to_owned),
            }
        }
    };
    let status = match entry.status() {
        ActivityStatus::Submitted => ActivityStatusSnapshot::Submitted,
        ActivityStatus::Pending => ActivityStatusSnapshot::Pending,
        ActivityStatus::Included(inclusion) => {
            ActivityStatusSnapshot::Included(activity_inclusion_snapshot(inclusion))
        }
        ActivityStatus::Reorged(inclusion) => {
            ActivityStatusSnapshot::Reorged(activity_inclusion_snapshot(inclusion))
        }
        ActivityStatus::DroppedCandidate => ActivityStatusSnapshot::DroppedCandidate,
        ActivityStatus::ReplacementSuspected => ActivityStatusSnapshot::ReplacementSuspected,
    };
    Ok(TransactionActivitySnapshot {
        submission_sequence: entry.submission_sequence(),
        transaction_hash: fixed_hex(identity.transaction_hash()),
        sender_account_index: identity.account_index(),
        sender_address: checksum_address(*identity.sender()),
        nonce: decimal_string(Word::from_be_bytes(*identity.nonce())),
        gas_limit: decimal_string(Word::from_be_bytes(*identity.gas_limit())),
        max_priority_fee_per_gas_gwei: format_gwei(Word::from_be_bytes(
            *identity.max_priority_fee_per_gas(),
        )),
        max_fee_per_gas_gwei: format_gwei(Word::from_be_bytes(*identity.max_fee_per_gas())),
        transfer,
        status,
    })
}

fn activity_inclusion_snapshot(inclusion: Inclusion) -> ActivityInclusionSnapshot {
    ActivityInclusionSnapshot {
        outcome: match inclusion.outcome() {
            InclusionOutcome::Success => ActivityInclusionOutcome::Success,
            InclusionOutcome::Revert => ActivityInclusionOutcome::Revert,
        },
        block_number: inclusion.block_number(),
        block_hash: fixed_hex(inclusion.block_hash()),
        observed_head_number: inclusion.observed_head_number(),
        observed_head_hash: fixed_hex(inclusion.observed_head_hash()),
        depth: u64::from(inclusion.depth()),
    }
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

/// Rebuild and locally authenticate the exact signed EIP-1559 envelope carried
/// by an RPC transaction object. The endpoint's `hash` and `from` fields are
/// never accepted as self-authenticating: canonical RLP, Keccak identity,
/// low-S/range validation, and public-key recovery must all agree first.
fn canonical_observed_type_two_bytes(
    transaction: &ActivityRpcTransaction,
) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    if transaction.y_parity > 1 || transaction.r.is_zero() || transaction.s.is_zero() {
        return Err(BackendError::ActivityObservationInvalid);
    }
    let signed_payload = rlp_list(&[
        rlp_word(Word::from_u64(rpc::SEPOLIA_CHAIN_ID)),
        rlp_word(transaction.nonce),
        rlp_word(transaction.priority_fee),
        rlp_word(transaction.maximum_fee),
        rlp_word(transaction.gas_limit),
        rlp_bytes(&transaction.to),
        rlp_word(transaction.value),
        rlp_bytes(transaction.input.as_slice()),
        rlp_list(&[]),
        rlp_integer(&[transaction.y_parity]),
        rlp_word(transaction.r),
        rlp_word(transaction.s),
    ]);
    let mut raw = Zeroizing::new(Vec::with_capacity(signed_payload.len() + 1));
    raw.push(2);
    raw.extend_from_slice(&signed_payload);
    if !(2..=MAX_PENDING_RAW_BYTES).contains(&raw.len())
        || keccak32(raw.as_slice()) != transaction.hash
        || recover_signed_type_two_sender(raw.as_slice())
            .map_err(|_| BackendError::ActivityObservationInvalid)?
            != transaction.from
    {
        return Err(BackendError::ActivityObservationInvalid);
    }
    Ok(raw)
}

struct DecodedPendingActivity {
    nonce: Word,
    gas_limit: Word,
    priority_fee: Word,
    maximum_fee: Word,
    transfer: DecodedPendingTransfer,
}

enum DecodedPendingTransfer {
    Native {
        recipient: [u8; 20],
        value: Word,
    },
    Erc20 {
        contract: [u8; 20],
        recipient: [u8; 20],
        raw_amount: [u8; 32],
    },
}

#[derive(Clone, Copy)]
struct DecodedRlpItem<'a> {
    encoded: &'a [u8],
    payload: &'a [u8],
    is_list: bool,
}

fn recover_signed_type_two_sender(raw: &[u8]) -> Result<[u8; 20], BackendError> {
    if !(2..=MAX_PENDING_RAW_BYTES).contains(&raw.len()) || raw.first() != Some(&2) {
        return Err(BackendError::PendingInvalid);
    }
    let (top, consumed) = decode_canonical_rlp_item(&raw[1..], 0)?;
    if !top.is_list || consumed != raw.len() - 1 {
        return Err(BackendError::PendingInvalid);
    }

    let empty = DecodedRlpItem {
        encoded: &top.payload[..0],
        payload: &top.payload[..0],
        is_list: false,
    };
    let mut fields = [empty; 12];
    let mut cursor = 0;
    for field in &mut fields {
        let (decoded, next) = decode_canonical_rlp_item(top.payload, cursor)?;
        *field = decoded;
        cursor = next;
    }
    if cursor != top.payload.len() {
        return Err(BackendError::PendingInvalid);
    }

    let chain_id = canonical_rlp_word(fields[0])?;
    let _nonce = canonical_rlp_word(fields[1])?;
    let priority_fee = canonical_rlp_word(fields[2])?;
    let maximum_fee = canonical_rlp_word(fields[3])?;
    let gas_limit = canonical_rlp_word(fields[4])?;
    if chain_id != Word::from_u64(rpc::SEPOLIA_CHAIN_ID) {
        return Err(BackendError::PendingInvalid);
    }
    validate_fee_quote(priority_fee, maximum_fee).map_err(|_| BackendError::PendingInvalid)?;
    if fields[5].is_list || fields[5].payload.len() != 20 || fields[5].payload == [0_u8; 20] {
        return Err(BackendError::PendingInvalid);
    }
    let value = canonical_rlp_word(fields[6])?;
    if fields[7].is_list || !fields[8].is_list || !fields[8].payload.is_empty() {
        return Err(BackendError::PendingInvalid);
    }
    let gas_limit_u64 = gas_limit.to_u64().ok_or(BackendError::PendingInvalid)?;
    let supported_native = fields[7].payload.is_empty()
        && gas_limit_u64 == NATIVE_TRANSFER_GAS
        && !value.is_zero()
        && value <= Word::from_u64(MAX_TRANSFER_WEI);
    let supported_erc20 = fields[7].payload.len() == 68
        && fields[7].payload.get(..4) == Some(erc20::TRANSFER_SELECTOR.as_slice())
        && fields[7].payload.get(4..16) == Some(&[0_u8; 12][..])
        && fields[7].payload.get(16..36) != Some(&[0_u8; 20][..])
        && fields[7].payload.get(36..68) != Some(&[0_u8; 32][..])
        && value.is_zero()
        && (MIN_ERC20_TRANSFER_GAS_LIMIT..=MAX_ERC20_TRANSFER_GAS_LIMIT).contains(&gas_limit_u64);
    if !supported_native && !supported_erc20 {
        return Err(BackendError::PendingInvalid);
    }

    let y_parity = canonical_rlp_word(fields[9])?
        .to_u64()
        .filter(|value| *value <= 1)
        .ok_or(BackendError::PendingInvalid)? as u8;
    let r = canonical_rlp_nonzero_scalar(fields[10])?;
    let s = canonical_rlp_nonzero_scalar(fields[11])?;
    const HALF_CURVE_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];
    if s > HALF_CURVE_ORDER {
        return Err(BackendError::PendingInvalid);
    }

    let unsigned_items = fields[..9]
        .iter()
        .map(|field| field.encoded.to_vec())
        .collect::<Vec<_>>();
    let unsigned_payload = rlp_list(&unsigned_items);
    let mut unsigned = Zeroizing::new(Vec::with_capacity(unsigned_payload.len() + 1));
    unsigned.push(2);
    unsigned.extend_from_slice(&unsigned_payload);
    let mut prehash = keccak32(unsigned.as_slice());
    let mut compact = Zeroizing::new([0_u8; 64]);
    compact[..32].copy_from_slice(&r);
    compact[32..].copy_from_slice(&s);
    let recoverable = RecoverableSignature::from_compact(
        compact.as_slice(),
        RecoveryId::try_from(i32::from(y_parity)).map_err(|_| BackendError::PendingInvalid)?,
    )
    .map_err(|_| BackendError::PendingInvalid)?;
    let recovered = Secp256k1::new()
        .recover_ecdsa(Message::from_digest(prehash), &recoverable)
        .map_err(|_| BackendError::PendingInvalid)?;
    prehash.zeroize();
    Ok(address_from_public_key(&recovered))
}

fn decode_pending_activity(raw: &[u8]) -> Result<DecodedPendingActivity, BackendError> {
    if !(2..=MAX_PENDING_RAW_BYTES).contains(&raw.len()) || raw.first() != Some(&2) {
        return Err(BackendError::PendingInvalid);
    }
    let (top, consumed) = decode_canonical_rlp_item(&raw[1..], 0)?;
    if !top.is_list || consumed != raw.len() - 1 {
        return Err(BackendError::PendingInvalid);
    }
    let empty = DecodedRlpItem {
        encoded: &top.payload[..0],
        payload: &top.payload[..0],
        is_list: false,
    };
    let mut fields = [empty; 12];
    let mut cursor = 0;
    for field in &mut fields {
        let (decoded, next) = decode_canonical_rlp_item(top.payload, cursor)?;
        *field = decoded;
        cursor = next;
    }
    if cursor != top.payload.len()
        || canonical_rlp_word(fields[0])? != Word::from_u64(rpc::SEPOLIA_CHAIN_ID)
        || fields[5].is_list
        || fields[5].payload.len() != 20
        || fields[5].payload == [0_u8; 20]
        || fields[7].is_list
        || !fields[8].is_list
        || !fields[8].payload.is_empty()
    {
        return Err(BackendError::PendingInvalid);
    }
    let nonce = canonical_rlp_word(fields[1])?;
    let priority_fee = canonical_rlp_word(fields[2])?;
    let maximum_fee = canonical_rlp_word(fields[3])?;
    let gas_limit = canonical_rlp_word(fields[4])?;
    let value = canonical_rlp_word(fields[6])?;
    validate_fee_quote(priority_fee, maximum_fee).map_err(|_| BackendError::PendingInvalid)?;
    let destination: [u8; 20] = fields[5]
        .payload
        .try_into()
        .map_err(|_| BackendError::PendingInvalid)?;
    let gas_limit_u64 = gas_limit.to_u64().ok_or(BackendError::PendingInvalid)?;
    let transfer = if fields[7].payload.is_empty()
        && gas_limit_u64 == NATIVE_TRANSFER_GAS
        && !value.is_zero()
        && value <= Word::from_u64(MAX_TRANSFER_WEI)
    {
        DecodedPendingTransfer::Native {
            recipient: destination,
            value,
        }
    } else if fields[7].payload.len() == 68
        && fields[7].payload.get(..4) == Some(erc20::TRANSFER_SELECTOR.as_slice())
        && fields[7].payload.get(4..16) == Some(&[0_u8; 12][..])
        && fields[7].payload.get(16..36) != Some(&[0_u8; 20][..])
        && fields[7].payload.get(36..68) != Some(&[0_u8; 32][..])
        && value.is_zero()
        && (MIN_ERC20_TRANSFER_GAS_LIMIT..=MAX_ERC20_TRANSFER_GAS_LIMIT).contains(&gas_limit_u64)
    {
        DecodedPendingTransfer::Erc20 {
            contract: destination,
            recipient: fields[7].payload[16..36]
                .try_into()
                .map_err(|_| BackendError::PendingInvalid)?,
            raw_amount: fields[7].payload[36..68]
                .try_into()
                .map_err(|_| BackendError::PendingInvalid)?,
        }
    } else {
        return Err(BackendError::PendingInvalid);
    };
    // Reuse the full low-S canonical recovery check so this projection cannot
    // accept a transaction identity the pending attribution path would reject.
    let _ = recover_signed_type_two_sender(raw)?;
    Ok(DecodedPendingActivity {
        nonce,
        gas_limit,
        priority_fee,
        maximum_fee,
        transfer,
    })
}

fn decode_canonical_rlp_item(
    input: &[u8],
    offset: usize,
) -> Result<(DecodedRlpItem<'_>, usize), BackendError> {
    let prefix = *input.get(offset).ok_or(BackendError::PendingInvalid)?;
    if prefix <= 0x7f {
        let end = offset.checked_add(1).ok_or(BackendError::PendingInvalid)?;
        return Ok((
            DecodedRlpItem {
                encoded: input.get(offset..end).ok_or(BackendError::PendingInvalid)?,
                payload: input.get(offset..end).ok_or(BackendError::PendingInvalid)?,
                is_list: false,
            },
            end,
        ));
    }
    let (is_list, header_length, payload_length) = match prefix {
        0x00..=0x7f => return Err(BackendError::PendingInvalid),
        0x80..=0xb7 => (false, 1, usize::from(prefix - 0x80)),
        0xb8..=0xbf => {
            let length_bytes = usize::from(prefix - 0xb7);
            (
                false,
                1 + length_bytes,
                decode_long_rlp_length(input, offset, length_bytes)?,
            )
        }
        0xc0..=0xf7 => (true, 1, usize::from(prefix - 0xc0)),
        0xf8..=0xff => {
            let length_bytes = usize::from(prefix - 0xf7);
            (
                true,
                1 + length_bytes,
                decode_long_rlp_length(input, offset, length_bytes)?,
            )
        }
    };
    let payload_start = offset
        .checked_add(header_length)
        .ok_or(BackendError::PendingInvalid)?;
    let end = payload_start
        .checked_add(payload_length)
        .ok_or(BackendError::PendingInvalid)?;
    let payload = input
        .get(payload_start..end)
        .ok_or(BackendError::PendingInvalid)?;
    if !is_list && payload_length == 1 && payload[0] < 0x80 {
        return Err(BackendError::PendingInvalid);
    }
    Ok((
        DecodedRlpItem {
            encoded: input.get(offset..end).ok_or(BackendError::PendingInvalid)?,
            payload,
            is_list,
        },
        end,
    ))
}

fn decode_long_rlp_length(
    input: &[u8],
    offset: usize,
    length_bytes: usize,
) -> Result<usize, BackendError> {
    if length_bytes == 0 || length_bytes > std::mem::size_of::<usize>() {
        return Err(BackendError::PendingInvalid);
    }
    let start = offset.checked_add(1).ok_or(BackendError::PendingInvalid)?;
    let end = start
        .checked_add(length_bytes)
        .ok_or(BackendError::PendingInvalid)?;
    let encoded = input.get(start..end).ok_or(BackendError::PendingInvalid)?;
    if encoded.first() == Some(&0) {
        return Err(BackendError::PendingInvalid);
    }
    let mut length = 0_usize;
    for byte in encoded {
        length = length
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .ok_or(BackendError::PendingInvalid)?;
    }
    if length <= 55 {
        return Err(BackendError::PendingInvalid);
    }
    Ok(length)
}

fn canonical_rlp_word(item: DecodedRlpItem<'_>) -> Result<Word, BackendError> {
    if item.is_list || item.payload.len() > 32 || item.payload.first() == Some(&0) {
        return Err(BackendError::PendingInvalid);
    }
    let mut bytes = [0_u8; 32];
    bytes[32 - item.payload.len()..].copy_from_slice(item.payload);
    Ok(Word::from_be_bytes(bytes))
}

fn canonical_rlp_nonzero_scalar(item: DecodedRlpItem<'_>) -> Result<[u8; 32], BackendError> {
    let value = canonical_rlp_word(item)?;
    if value.is_zero() {
        return Err(BackendError::PendingInvalid);
    }
    Ok(*value.as_be_bytes())
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

/// Sign exactly one ERC-20 `transfer(address,uint256)` type-2 transaction.
///
/// No caller can provide arbitrary calldata: the fixed 68-byte ABI payload is
/// constructed here from the already-validated recipient and amount, with the
/// contract as `to` and zero native value.
#[allow(clippy::too_many_arguments)]
fn sign_erc20_type_two(
    signing_material: &[u8; 32],
    expected_sender: [u8; 20],
    contract: [u8; 20],
    recipient: [u8; 20],
    amount: TokenAmount,
    nonce: Word,
    gas_limit: Word,
    priority_fee: Word,
    maximum_fee: Word,
) -> Result<SignedTransaction, BackendError> {
    validate_fee_quote(priority_fee, maximum_fee)?;
    let gas_limit_u64 = gas_limit.to_u64().ok_or(BackendError::PreparedInvalid)?;
    if contract == [0; 20]
        || recipient == [0; 20]
        || amount.is_zero()
        || !(MIN_ERC20_TRANSFER_GAS_LIMIT..=MAX_ERC20_TRANSFER_GAS_LIMIT).contains(&gas_limit_u64)
    {
        return Err(BackendError::PreparedInvalid);
    }
    let calldata = erc20::transfer_call_data(recipient, amount);
    let chain_id = Word::from_u64(rpc::SEPOLIA_CHAIN_ID);
    let unsigned_payload = rlp_list(&[
        rlp_word(chain_id),
        rlp_word(nonce),
        rlp_word(priority_fee),
        rlp_word(maximum_fee),
        rlp_word(gas_limit),
        rlp_bytes(&contract),
        rlp_word(Word::ZERO),
        rlp_bytes(&calldata),
        rlp_list(&[]),
    ]);
    let mut unsigned = Zeroizing::new(Vec::with_capacity(unsigned_payload.len() + 1));
    unsigned.push(2);
    unsigned.extend_from_slice(&unsigned_payload);
    let mut prehash = keccak32(unsigned.as_slice());
    let secret = SecretKey::from_byte_array(*signing_material)
        .map_err(|_| BackendError::CryptographicFailure)?;
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
        rlp_bytes(&contract),
        rlp_word(Word::ZERO),
        rlp_bytes(&calldata),
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
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    const TEST_PASSWORD: &str = "correct demo password";

    #[cfg(windows)]
    fn windows_file_identity(file: &File) -> (u64, [u8; 16]) {
        use core::ffi::c_void;
        use core::mem::size_of_val;
        use core::ptr;
        use windows::Win32::Storage::FileSystem::{
            FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
        };

        let mut information = FILE_ID_INFO::default();
        // SAFETY: the handle is borrowed from the simultaneously live `File`,
        // and the output points at exact writable `FILE_ID_INFO` storage.
        unsafe {
            GetFileInformationByHandleEx(
                HANDLE(file.as_raw_handle()),
                FileIdInfo,
                ptr::from_mut(&mut information).cast::<c_void>(),
                u32::try_from(size_of_val(&information)).expect("FILE_ID_INFO size fits u32"),
            )
        }
        .expect("query exact Windows file identity");
        (
            information.VolumeSerialNumber,
            information.FileId.Identifier,
        )
    }

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

        fn send_raw_transaction(
            &self,
            signed: &[u8],
            permit: &SessionPermit<'_>,
        ) -> Result<[u8; 32], SendRawError> {
            if !permit.is_current() {
                return Err(SendRawError::SessionRevoked);
            }
            if self.send_fails {
                Err(SendRawError::BroadcastUnknown)
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
    struct TokenRpc {
        state: Arc<Mutex<TokenRpcState>>,
    }

    struct TokenRpcState {
        verify_ok: bool,
        verify_calls: usize,
        fail_verify_on_call: Option<usize>,
        query_fails: bool,
        query_calls: usize,
        replace_on_query: Option<(usize, [u8; 20], TokenFixture)>,
        contracts: HashMap<[u8; 20], TokenFixture>,
        native_balance: Word,
        nonce: Word,
        base_fee: Word,
        priority_fee: Word,
        maximum_fee: Word,
        token_estimated_gas: Word,
        transfer_result: Vec<u8>,
        preflight_calls: usize,
        estimate_calls: usize,
        nonce_calls: usize,
        quote_calls: usize,
        base_fee_calls: usize,
        native_balance_calls: usize,
        balance_owners: Vec<[u8; 20]>,
        estimate_senders: Vec<[u8; 20]>,
        preflight_fields: Vec<TokenPreflightObservation>,
        sent: Vec<Vec<u8>>,
        send_fails: bool,
        activity_head: ActivityRpcBlock,
        observed_transaction: Option<ActivityRpcTransaction>,
        activity_transaction_calls: usize,
    }

    #[derive(Clone)]
    struct TokenFixture {
        code: Vec<u8>,
        decimals: Vec<u8>,
        symbol: Vec<u8>,
        balance: Vec<u8>,
    }

    #[derive(Clone, Copy)]
    struct TokenPreflightObservation {
        sender: [u8; 20],
        contract: [u8; 20],
        recipient: [u8; 20],
        amount: TokenAmount,
        nonce: Word,
        gas_limit: Word,
        priority_fee: Word,
        maximum_fee: Word,
    }

    impl TokenRpc {
        fn new() -> Self {
            Self {
                state: Arc::new(Mutex::new(TokenRpcState {
                    verify_ok: true,
                    verify_calls: 0,
                    fail_verify_on_call: None,
                    query_fails: false,
                    query_calls: 0,
                    replace_on_query: None,
                    contracts: HashMap::new(),
                    native_balance: Word::from_u64(2_000_000_000_000_000_000),
                    nonce: Word::from_u64(7),
                    base_fee: Word::from_u64(500_000_000),
                    priority_fee: Word::from_u64(1_000_000_000),
                    maximum_fee: Word::from_u64(2_000_000_000),
                    token_estimated_gas: Word::from_u64(50_000),
                    transfer_result: abi_u8(1),
                    preflight_calls: 0,
                    estimate_calls: 0,
                    nonce_calls: 0,
                    quote_calls: 0,
                    base_fee_calls: 0,
                    native_balance_calls: 0,
                    balance_owners: Vec::new(),
                    estimate_senders: Vec::new(),
                    preflight_fields: Vec::new(),
                    sent: Vec::new(),
                    send_fails: false,
                    activity_head: ActivityRpcBlock {
                        number: 100,
                        hash: [0xa0; 32],
                    },
                    observed_transaction: None,
                    activity_transaction_calls: 0,
                })),
            }
        }

        fn insert(&self, contract: [u8; 20], fixture: TokenFixture) {
            self.state
                .lock()
                .expect("token RPC lock")
                .contracts
                .insert(contract, fixture);
        }

        fn update(&self, update: impl FnOnce(&mut TokenRpcState)) {
            update(&mut self.state.lock().expect("token RPC lock"));
        }

        fn response(
            &self,
            contract: [u8; 20],
            select: impl FnOnce(&TokenFixture) -> &[u8],
        ) -> Result<Vec<u8>, ()> {
            let mut state = self.state.lock().map_err(|_| ())?;
            if state.query_fails {
                return Err(());
            }
            state.query_calls = state.query_calls.checked_add(1).ok_or(())?;
            let replacement = state
                .replace_on_query
                .as_ref()
                .filter(|(call, _, _)| *call == state.query_calls)
                .cloned();
            if let Some((_, replacement_contract, fixture)) = replacement {
                state.replace_on_query = None;
                state.contracts.insert(replacement_contract, fixture);
            }
            state
                .contracts
                .get(&contract)
                .map(select)
                .map(<[u8]>::to_vec)
                .ok_or(())
        }
    }

    impl RpcAccess for TokenRpc {
        fn verify_sepolia(&self) -> Result<(), ()> {
            let mut state = self.state.lock().map_err(|_| ())?;
            state.verify_calls = state.verify_calls.checked_add(1).ok_or(())?;
            (state.verify_ok && state.fail_verify_on_call != Some(state.verify_calls))
                .then_some(())
                .ok_or(())
        }

        fn balance(&self, _address: [u8; 20]) -> Result<Word, ()> {
            Ok(self.state.lock().map_err(|_| ())?.native_balance)
        }

        fn pending_balance(&self, _address: [u8; 20]) -> Result<Word, ()> {
            let mut state = self.state.lock().map_err(|_| ())?;
            state.native_balance_calls += 1;
            Ok(state.native_balance)
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
                recommended_priority_fee: state.priority_fee,
                recommended_maximum_fee: state.maximum_fee,
            })
        }

        fn latest_base_fee(&self) -> Result<Word, ()> {
            let mut state = self.state.lock().map_err(|_| ())?;
            state.base_fee_calls += 1;
            Ok(state.base_fee)
        }

        fn latest_nonce(&self, _address: [u8; 20]) -> Result<Word, ()> {
            Ok(self.state.lock().map_err(|_| ())?.nonce)
        }

        fn activity_transaction(
            &self,
            transaction_hash: [u8; 32],
        ) -> Result<Option<ActivityRpcTransaction>, ()> {
            let mut state = self.state.lock().map_err(|_| ())?;
            state.activity_transaction_calls += 1;
            match state.observed_transaction.as_ref() {
                Some(transaction) if transaction.hash != transaction_hash => Err(()),
                transaction => Ok(transaction.cloned()),
            }
        }

        fn activity_head(&self) -> Result<ActivityRpcBlock, ()> {
            Ok(self.state.lock().map_err(|_| ())?.activity_head)
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
            Err(())
        }

        fn send_raw_transaction(
            &self,
            signed: &[u8],
            permit: &SessionPermit<'_>,
        ) -> Result<[u8; 32], SendRawError> {
            if !permit.is_current() {
                return Err(SendRawError::SessionRevoked);
            }
            let mut state = self
                .state
                .lock()
                .map_err(|_| SendRawError::BroadcastUnknown)?;
            state.sent.push(signed.to_vec());
            if state.send_fails {
                Err(SendRawError::BroadcastUnknown)
            } else {
                Ok(keccak32(signed))
            }
        }

        fn contract_code(&self, contract: [u8; 20]) -> Result<Vec<u8>, ()> {
            self.response(contract, |fixture| fixture.code.as_slice())
        }

        fn erc20_decimals(&self, contract: [u8; 20]) -> Result<Vec<u8>, ()> {
            self.response(contract, |fixture| fixture.decimals.as_slice())
        }

        fn erc20_symbol(&self, contract: [u8; 20]) -> Result<Vec<u8>, ()> {
            self.response(contract, |fixture| fixture.symbol.as_slice())
        }

        fn erc20_balance_of(&self, contract: [u8; 20], owner: [u8; 20]) -> Result<Vec<u8>, ()> {
            self.state
                .lock()
                .map_err(|_| ())?
                .balance_owners
                .push(owner);
            self.response(contract, |fixture| fixture.balance.as_slice())
        }

        fn erc20_transfer_preflight(
            &self,
            sender: [u8; 20],
            contract: [u8; 20],
            recipient: [u8; 20],
            amount: TokenAmount,
            nonce: Word,
            gas_limit: Word,
            priority_fee: Word,
            maximum_fee: Word,
        ) -> Result<Vec<u8>, ()> {
            let mut state = self.state.lock().map_err(|_| ())?;
            state.preflight_calls += 1;
            state.preflight_fields.push(TokenPreflightObservation {
                sender,
                contract,
                recipient,
                amount,
                nonce,
                gas_limit,
                priority_fee,
                maximum_fee,
            });
            Ok(state.transfer_result.clone())
        }

        fn estimate_erc20_transfer_gas(
            &self,
            sender: [u8; 20],
            _contract: [u8; 20],
            _recipient: [u8; 20],
            _amount: TokenAmount,
            _nonce: Word,
            _priority_fee: Word,
            _maximum_fee: Word,
        ) -> Result<Word, ()> {
            let mut state = self.state.lock().map_err(|_| ())?;
            state.estimate_calls += 1;
            state.estimate_senders.push(sender);
            Ok(state.token_estimated_gas)
        }
    }

    fn abi_u8(value: u8) -> Vec<u8> {
        let mut word = vec![0_u8; 32];
        word[31] = value;
        word
    }

    fn abi_symbol(value: &str) -> Vec<u8> {
        let mut output = vec![0_u8; 96];
        output[31] = 32;
        output[63] = u8::try_from(value.len()).expect("bounded test symbol");
        output[64..64 + value.len()].copy_from_slice(value.as_bytes());
        output
    }

    fn token_fixture(marker: u8) -> TokenFixture {
        let mut balance = vec![0_u8; 32];
        balance[30..].copy_from_slice(&(1_234_u16 + u16::from(marker)).to_be_bytes());
        TokenFixture {
            code: vec![0x60, marker, 0x60, 0x00],
            decimals: abi_u8(2),
            symbol: abi_symbol("TOK"),
            balance,
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
    struct ExpireOnCallClock {
        start: Instant,
        calls: Arc<Mutex<usize>>,
        expire_on_call: usize,
    }

    impl ExpireOnCallClock {
        fn new(start: Instant, expire_on_call: usize) -> Self {
            Self {
                start,
                calls: Arc::new(Mutex::new(0)),
                expire_on_call,
            }
        }

        fn calls(&self) -> usize {
            *self.calls.lock().expect("expiry clock calls")
        }
    }

    impl MonotonicClock for ExpireOnCallClock {
        fn now(&self) -> Instant {
            let mut calls = self.calls.lock().expect("expiry clock lock");
            *calls += 1;
            if *calls >= self.expire_on_call {
                self.start + GENERATED_BACKUP_TTL
            } else {
                self.start
            }
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
        balance_addresses: Vec<[u8; 20]>,
        pending_balance_addresses: Vec<[u8; 20]>,
        nonce_addresses: Vec<[u8; 20]>,
        estimate_senders: Vec<[u8; 20]>,
        sent: Vec<Vec<u8>>,
        send_fails: bool,
        pending_path_to_require: Option<PathBuf>,
        send_observed_pending: bool,
        send_observed_exact_pending: bool,
        revoke_epoch_after_send: Option<Arc<std::sync::atomic::AtomicU64>>,
        expire_clock_on_estimate_call: Option<(TestClock, usize, Duration)>,
        observed_transaction: Option<ActivityRpcTransaction>,
        activity_transaction_calls: usize,
        observed_receipt: Option<ActivityRpcReceipt>,
        canonical_blocks: Vec<ActivityRpcBlock>,
        activity_head: ActivityRpcBlock,
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
                    balance_addresses: Vec::new(),
                    pending_balance_addresses: Vec::new(),
                    nonce_addresses: Vec::new(),
                    estimate_senders: Vec::new(),
                    sent: Vec::new(),
                    send_fails: false,
                    pending_path_to_require: None,
                    send_observed_pending: false,
                    send_observed_exact_pending: false,
                    revoke_epoch_after_send: None,
                    expire_clock_on_estimate_call: None,
                    observed_transaction: None,
                    activity_transaction_calls: 0,
                    observed_receipt: None,
                    canonical_blocks: Vec::new(),
                    activity_head: ActivityRpcBlock {
                        number: 100,
                        hash: [0xa5; 32],
                    },
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

        fn balance(&self, address: [u8; 20]) -> Result<Word, ()> {
            let mut state = self.state.lock().map_err(|_| ())?;
            state.balance_addresses.push(address);
            Ok(state.balance)
        }

        fn pending_balance(&self, address: [u8; 20]) -> Result<Word, ()> {
            let mut state = self.state.lock().map_err(|_| ())?;
            state.balance_calls += 1;
            state.pending_balance_addresses.push(address);
            Ok(state.balance)
        }

        fn pending_nonce(&self, address: [u8; 20]) -> Result<Word, ()> {
            let mut state = self.state.lock().map_err(|_| ())?;
            state.nonce_calls += 1;
            state.nonce_addresses.push(address);
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

        fn activity_transaction(
            &self,
            _transaction_hash: [u8; 32],
        ) -> Result<Option<ActivityRpcTransaction>, ()> {
            let mut state = self.state.lock().map_err(|_| ())?;
            state.activity_transaction_calls += 1;
            Ok(state.observed_transaction.clone())
        }

        fn activity_receipt(
            &self,
            _transaction_hash: [u8; 32],
        ) -> Result<Option<ActivityRpcReceipt>, ()> {
            self.state
                .lock()
                .map(|state| state.observed_receipt)
                .map_err(|_| ())
        }

        fn activity_block(&self, number: u64) -> Result<Option<ActivityRpcBlock>, ()> {
            self.state
                .lock()
                .map(|state| {
                    state
                        .canonical_blocks
                        .iter()
                        .copied()
                        .find(|block| block.number == number)
                })
                .map_err(|_| ())
        }

        fn activity_head(&self) -> Result<ActivityRpcBlock, ()> {
            self.state
                .lock()
                .map(|state| state.activity_head)
                .map_err(|_| ())
        }

        fn estimate_native_transfer_gas(
            &self,
            sender: [u8; 20],
            _recipient: [u8; 20],
            _value: Word,
            _nonce: Word,
            _priority_fee: Word,
            _maximum_fee: Word,
        ) -> Result<Word, ()> {
            let (gas, expiration) = {
                let mut state = self.state.lock().map_err(|_| ())?;
                state.estimate_calls += 1;
                state.estimate_senders.push(sender);
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

        fn send_raw_transaction(
            &self,
            signed: &[u8],
            permit: &SessionPermit<'_>,
        ) -> Result<[u8; 32], SendRawError> {
            if !permit.is_current() {
                return Err(SendRawError::SessionRevoked);
            }
            let mut state = self
                .state
                .lock()
                .map_err(|_| SendRawError::BroadcastUnknown)?;
            state.sent.push(signed.to_vec());
            if let Some(path) = state.pending_path_to_require.clone() {
                state.send_observed_pending = path.is_file();
                state.send_observed_exact_pending = read_pending(&path).map_or_else(
                    |_| {
                        // Production holds a zero-share exact-file lease from
                        // its own successful readback through transport. A
                        // second open failing while the path exists is the
                        // expected Windows proof that replacement is blocked.
                        path.is_file()
                    },
                    |pending| {
                        pending.transaction_hash == keccak32(signed)
                            && pending.raw_transaction.as_slice() == signed
                    },
                );
            }
            let result = if state.send_fails {
                Err(SendRawError::BroadcastUnknown)
            } else {
                Ok(keccak32(signed))
            };
            let revoke_epoch_after_send = state.revoke_epoch_after_send.clone();
            drop(state);
            if let Some(epoch) = revoke_epoch_after_send {
                epoch.store(1, std::sync::atomic::Ordering::SeqCst);
            }
            result
        }
    }

    /// One deterministic, cloneable RPC surface used by the full backend
    /// lifecycle regression. Native-transfer and ERC-20 calls intentionally
    /// share the same process state across backend restarts.
    #[derive(Clone)]
    struct LifecycleRpc {
        native: MutableRpc,
        tokens: TokenRpc,
    }

    impl RpcAccess for LifecycleRpc {
        fn verify_sepolia(&self) -> Result<(), ()> {
            self.native.verify_sepolia()
        }

        fn balance(&self, address: [u8; 20]) -> Result<Word, ()> {
            self.native.balance(address)
        }

        fn pending_balance(&self, address: [u8; 20]) -> Result<Word, ()> {
            self.native.pending_balance(address)
        }

        fn pending_nonce(&self, address: [u8; 20]) -> Result<Word, ()> {
            self.native.pending_nonce(address)
        }

        fn fee_quote(&self) -> Result<NetworkFeeQuote, ()> {
            self.native.fee_quote()
        }

        fn latest_base_fee(&self) -> Result<Word, ()> {
            self.native.latest_base_fee()
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
            self.native.estimate_native_transfer_gas(
                sender,
                recipient,
                value,
                nonce,
                priority_fee,
                maximum_fee,
            )
        }

        fn send_raw_transaction(
            &self,
            signed: &[u8],
            permit: &SessionPermit<'_>,
        ) -> Result<[u8; 32], SendRawError> {
            self.native.send_raw_transaction(signed, permit)
        }

        fn contract_code(&self, contract: [u8; 20]) -> Result<Vec<u8>, ()> {
            self.tokens.contract_code(contract)
        }

        fn erc20_decimals(&self, contract: [u8; 20]) -> Result<Vec<u8>, ()> {
            self.tokens.erc20_decimals(contract)
        }

        fn erc20_symbol(&self, contract: [u8; 20]) -> Result<Vec<u8>, ()> {
            self.tokens.erc20_symbol(contract)
        }

        fn erc20_balance_of(&self, contract: [u8; 20], owner: [u8; 20]) -> Result<Vec<u8>, ()> {
            self.tokens.erc20_balance_of(contract, owner)
        }

        fn erc20_transfer_preflight(
            &self,
            sender: [u8; 20],
            contract: [u8; 20],
            recipient: [u8; 20],
            amount: TokenAmount,
            nonce: Word,
            gas_limit: Word,
            priority_fee: Word,
            maximum_fee: Word,
        ) -> Result<Vec<u8>, ()> {
            self.tokens.erc20_transfer_preflight(
                sender,
                contract,
                recipient,
                amount,
                nonce,
                gas_limit,
                priority_fee,
                maximum_fee,
            )
        }

        fn estimate_erc20_transfer_gas(
            &self,
            sender: [u8; 20],
            contract: [u8; 20],
            recipient: [u8; 20],
            amount: TokenAmount,
            nonce: Word,
            priority_fee: Word,
            maximum_fee: Word,
        ) -> Result<Word, ()> {
            self.tokens.estimate_erc20_transfer_gas(
                sender,
                contract,
                recipient,
                amount,
                nonce,
                priority_fee,
                maximum_fee,
            )
        }
    }

    fn unlocked_backend(rpc: MutableRpc, clock: TestClock) -> DemoBackend {
        let vault = temporary_vault();
        if let Some(parent) = vault.parent() {
            fs::create_dir_all(parent).expect("create test backend directory");
        }
        let private_key = Zeroizing::new([7_u8; KEY_BYTES]);
        let wallet = WalletSecret::from_raw_private_key_bytes(private_key)
            .expect("build deterministic v2 test wallet");
        let metadata = confirmed_metadata(VaultOrigin::ImportedRawPrivateKey)
            .expect("build deterministic v2 test metadata");
        let password = matching_vault_password(sensitive(TEST_PASSWORD), sensitive(TEST_PASSWORD))
            .expect("build deterministic v2 test password");
        let sealed =
            seal_vault_v2(&wallet, &password, metadata).expect("seal deterministic v2 test wallet");
        let opened =
            open_vault_v2(sealed.as_bytes(), &password).expect("open deterministic v2 test wallet");
        let address = *opened
            .wallet()
            .account(0)
            .expect("v2 test account zero")
            .address()
            .as_bytes();
        let mut backend = DemoBackend::with_rpc_and_clock(vault, rpc, clock);
        backend.unlocked = Some(UnlockedWallet::V2(opened));
        backend.last_balance = Some(AccountBalance {
            account_index: 0,
            address,
            value: Word::ZERO,
        });
        backend
    }

    fn legacy_unlocked_backend(rpc: MutableRpc, clock: TestClock) -> DemoBackend {
        let vault = temporary_vault();
        if let Some(parent) = vault.parent() {
            fs::create_dir_all(parent).expect("create legacy test backend directory");
        }
        let private_key = Zeroizing::new([7_u8; KEY_BYTES]);
        let address = address_from_private_key(&private_key).expect("derive legacy test address");
        let mut backend = DemoBackend::with_rpc_and_clock(vault, rpc, clock);
        backend.unlocked = Some(UnlockedWallet::LegacyV1 {
            private_key,
            address,
        });
        backend.last_balance = Some(AccountBalance {
            account_index: 0,
            address,
            value: Word::ZERO,
        });
        backend
    }

    fn remove_test_backend_files(backend: &DemoBackend) {
        let _ = fs::remove_file(&backend.pending_path);
        let _ = fs::remove_file(&backend.vault_path);
        let _ = fs::remove_file(&backend.vault_v2_path);
        if let Ok(temporary) = vault_v2_migration_temporary_path(&backend.vault_v2_path) {
            let _ = fs::remove_file(&temporary);
            let _ = fs::remove_dir(&temporary);
        }
        let _ = fs::remove_file(&backend.token_store_path);
        let _ = fs::remove_dir(&backend.token_store_path);
        let _ = fs::remove_file(&backend.activity_store_path);
        let _ = fs::remove_dir(&backend.activity_store_path);
        if let Ok(temporary) = token_store_temporary_path(&backend.token_store_path) {
            let _ = fs::remove_file(&temporary);
            let _ = fs::remove_dir(&temporary);
        }
        if let Ok(lock) = token_store_lock_path(&backend.token_store_path) {
            let _ = fs::remove_file(&lock);
            let _ = fs::remove_dir(&lock);
        }
        if let Ok(temporary) = activity_store_temporary_path(&backend.activity_store_path) {
            let _ = fs::remove_file(&temporary);
            let _ = fs::remove_dir(&temporary);
        }
        if let Ok(lock) = activity_store_lock_path(&backend.activity_store_path) {
            let _ = fs::remove_file(&lock);
            let _ = fs::remove_dir(&lock);
        }
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

    fn native_prepared(backend: &DemoBackend) -> &PreparedNativeTransfer {
        match backend.prepared.as_ref().expect("prepared transfer") {
            PreparedTransfer::Native(prepared) => prepared,
            PreparedTransfer::SavedErc20(_) => panic!("test expected native prepared transfer"),
        }
    }

    fn observed_transaction_for_identity(identity: &TransactionIdentity) -> ActivityRpcTransaction {
        let (to, value, input) = match identity.transfer() {
            Transfer::Native { .. } => (
                *identity.transfer().recipient(),
                Word::from_be_bytes(
                    *identity
                        .transfer()
                        .native_value()
                        .expect("native test activity value"),
                ),
                Vec::new(),
            ),
            Transfer::SavedErc20 { .. } => {
                let contract = *identity
                    .transfer()
                    .contract()
                    .expect("ERC20 test activity contract");
                let amount = TokenAmount::from_be_bytes(
                    *identity
                        .transfer()
                        .raw_amount()
                        .expect("ERC20 test activity amount"),
                );
                (
                    contract,
                    Word::ZERO,
                    erc20::transfer_call_data(*identity.transfer().recipient(), amount).to_vec(),
                )
            }
        };
        let mut private_key_bytes = [0_u8; KEY_BYTES];
        private_key_bytes.fill(7);
        let private_key = Zeroizing::new(private_key_bytes);
        let signed = match identity.transfer() {
            Transfer::Native { .. } => sign_native_type_two(
                &private_key,
                *identity.sender(),
                to,
                value,
                Word::from_be_bytes(*identity.nonce()),
                Word::from_be_bytes(*identity.gas_limit()),
                Word::from_be_bytes(*identity.max_priority_fee_per_gas()),
                Word::from_be_bytes(*identity.max_fee_per_gas()),
            ),
            Transfer::SavedErc20 { .. } => sign_erc20_type_two(
                &private_key,
                *identity.sender(),
                to,
                *identity.transfer().recipient(),
                TokenAmount::from_be_bytes(
                    *identity
                        .transfer()
                        .raw_amount()
                        .expect("ERC20 test activity amount"),
                ),
                Word::from_be_bytes(*identity.nonce()),
                Word::from_be_bytes(*identity.gas_limit()),
                Word::from_be_bytes(*identity.max_priority_fee_per_gas()),
                Word::from_be_bytes(*identity.max_fee_per_gas()),
            ),
        }
        .expect("sign observed transaction fixture");
        assert_eq!(
            signed.transaction_hash,
            *identity.transaction_hash(),
            "activity identity must bind the exact signed fixture"
        );
        let (top, consumed) =
            decode_canonical_rlp_item(&signed.bytes[1..], 0).expect("decode signed fixture");
        assert!(top.is_list && consumed == signed.bytes.len() - 1);
        let empty = DecodedRlpItem {
            encoded: &top.payload[..0],
            payload: &top.payload[..0],
            is_list: false,
        };
        let mut fields = [empty; 12];
        let mut cursor = 0;
        for field in &mut fields {
            let (decoded, next) =
                decode_canonical_rlp_item(top.payload, cursor).expect("decode signed field");
            *field = decoded;
            cursor = next;
        }
        assert_eq!(cursor, top.payload.len());
        let y_parity = u8::try_from(
            canonical_rlp_word(fields[9])
                .expect("canonical y parity")
                .to_u64()
                .expect("bounded y parity"),
        )
        .expect("u8 y parity");
        ActivityRpcTransaction {
            hash: *identity.transaction_hash(),
            from: *identity.sender(),
            to,
            nonce: Word::from_be_bytes(*identity.nonce()),
            value,
            input,
            gas_limit: Word::from_be_bytes(*identity.gas_limit()),
            priority_fee: Word::from_be_bytes(*identity.max_priority_fee_per_gas()),
            maximum_fee: Word::from_be_bytes(*identity.max_fee_per_gas()),
            y_parity,
            r: canonical_rlp_word(fields[10]).expect("canonical r scalar"),
            s: canonical_rlp_word(fields[11]).expect("canonical s scalar"),
            block: None,
            transaction_index: None,
        }
    }

    fn observed_transaction_from_exact_pending(
        identity: &TransactionIdentity,
        raw: &[u8],
    ) -> ActivityRpcTransaction {
        assert_eq!(keccak32(raw), *identity.transaction_hash());
        assert_eq!(
            recover_signed_type_two_sender(raw).expect("recover pending observation sender"),
            *identity.sender()
        );
        let decoded = decode_pending_activity(raw).expect("decode exact pending observation");
        assert_eq!(decoded.nonce.as_be_bytes(), identity.nonce());
        assert_eq!(decoded.gas_limit.as_be_bytes(), identity.gas_limit());
        assert_eq!(
            decoded.priority_fee.as_be_bytes(),
            identity.max_priority_fee_per_gas()
        );
        assert_eq!(
            decoded.maximum_fee.as_be_bytes(),
            identity.max_fee_per_gas()
        );
        let (to, value, input) = match decoded.transfer {
            DecodedPendingTransfer::Native { recipient, value } => {
                assert_eq!(identity.transfer().recipient(), &recipient);
                assert_eq!(
                    identity.transfer().native_value(),
                    Some(value.as_be_bytes())
                );
                (recipient, value, Vec::new())
            }
            DecodedPendingTransfer::Erc20 {
                contract,
                recipient,
                raw_amount,
            } => {
                assert_eq!(identity.transfer().contract(), Some(&contract));
                assert_eq!(identity.transfer().recipient(), &recipient);
                assert_eq!(identity.transfer().raw_amount(), Some(&raw_amount));
                (
                    contract,
                    Word::ZERO,
                    erc20::transfer_call_data(recipient, TokenAmount::from_be_bytes(raw_amount))
                        .to_vec(),
                )
            }
        };
        let (top, consumed) =
            decode_canonical_rlp_item(&raw[1..], 0).expect("decode exact pending envelope");
        assert!(top.is_list && consumed == raw.len() - 1);
        let empty = DecodedRlpItem {
            encoded: &top.payload[..0],
            payload: &top.payload[..0],
            is_list: false,
        };
        let mut fields = [empty; 12];
        let mut cursor = 0;
        for field in &mut fields {
            let (decoded, next) =
                decode_canonical_rlp_item(top.payload, cursor).expect("decode exact pending field");
            *field = decoded;
            cursor = next;
        }
        assert_eq!(cursor, top.payload.len());
        ActivityRpcTransaction {
            hash: *identity.transaction_hash(),
            from: *identity.sender(),
            to,
            nonce: Word::from_be_bytes(*identity.nonce()),
            value,
            input,
            gas_limit: Word::from_be_bytes(*identity.gas_limit()),
            priority_fee: Word::from_be_bytes(*identity.max_priority_fee_per_gas()),
            maximum_fee: Word::from_be_bytes(*identity.max_fee_per_gas()),
            y_parity: u8::try_from(
                canonical_rlp_word(fields[9])
                    .expect("pending y parity")
                    .to_u64()
                    .expect("bounded pending y parity"),
            )
            .expect("u8 pending y parity"),
            r: canonical_rlp_word(fields[10]).expect("pending r scalar"),
            s: canonical_rlp_word(fields[11]).expect("pending s scalar"),
            block: None,
            transaction_index: None,
        }
    }

    fn rpc_quantity_fixture(value: Word) -> String {
        let bytes = value.as_be_bytes();
        let first = bytes.iter().position(|byte| *byte != 0);
        first.map_or_else(
            || "0x0".to_owned(),
            |index| {
                let encoded = hex_without_prefix(&bytes[index..]);
                format!("0x{}", encoded.trim_start_matches('0'))
            },
        )
    }

    fn rpc_transaction_fixture(transaction: &ActivityRpcTransaction) -> serde_json::Value {
        serde_json::json!({
            "hash": fixed_hex(&transaction.hash),
            "from": fixed_hex(&transaction.from),
            "to": fixed_hex(&transaction.to),
            "nonce": rpc_quantity_fixture(transaction.nonce),
            "value": rpc_quantity_fixture(transaction.value),
            "input": fixed_hex(transaction.input.as_slice()),
            "gas": rpc_quantity_fixture(transaction.gas_limit),
            "type": "0x2",
            "chainId": "0xaa36a7",
            "maxPriorityFeePerGas": rpc_quantity_fixture(transaction.priority_fee),
            "maxFeePerGas": rpc_quantity_fixture(transaction.maximum_fee),
            "accessList": [],
            "blockNumber": null,
            "blockHash": null,
            "blockTimestamp": null,
            "gasPrice": rpc_quantity_fixture(transaction.maximum_fee),
            "transactionIndex": null,
            "r": rpc_quantity_fixture(transaction.r),
            "s": rpc_quantity_fixture(transaction.s),
            "v": rpc_quantity_fixture(Word::from_u64(u64::from(transaction.y_parity))),
            "yParity": rpc_quantity_fixture(Word::from_u64(u64::from(transaction.y_parity))),
        })
    }

    fn submitted_activity_backend(rpc: MutableRpc) -> (DemoBackend, TransactionIdentity) {
        let backend = unlocked_backend(rpc, TestClock::new(Instant::now()));
        let (_, sender) = backend.selected_account().expect("selected test account");
        let mut private_key_bytes = [0_u8; KEY_BYTES];
        private_key_bytes.fill(7);
        let private_key = Zeroizing::new(private_key_bytes);
        let signed = sign_native_type_two(
            &private_key,
            sender,
            [0x92; 20],
            Word::from_u64(1_000_000_000_000_000),
            Word::from_u64(7),
            Word::from_u64(NATIVE_TRANSFER_GAS),
            Word::from_u64(1_000_000_000),
            Word::from_u64(2_000_000_000),
        )
        .expect("sign submitted activity fixture");
        let identity = TransactionIdentity::native(
            signed.transaction_hash,
            sender,
            0,
            *Word::from_u64(7).as_be_bytes(),
            *Word::from_u64(NATIVE_TRANSFER_GAS).as_be_bytes(),
            *Word::from_u64(1_000_000_000).as_be_bytes(),
            *Word::from_u64(2_000_000_000).as_be_bytes(),
            [0x92; 20],
            *Word::from_u64(1_000_000_000_000_000).as_be_bytes(),
        )
        .expect("submitted activity identity");
        let context = backend.activity_context().expect("v2 activity context");
        let activity_lease = ActivityMutationLease::acquire(&backend.activity_store_path)
            .expect("activity mutation lease");
        let mut loaded = backend
            .load_activity_store(&context)
            .expect("empty activity store");
        backend
            .commit_submitted_activity(&activity_lease, &context, &mut loaded, &identity)
            .expect("commit submitted activity fixture");
        drop(activity_lease);
        (backend, identity)
    }

    #[test]
    fn observed_type_two_requires_canonical_hash_signature_and_recovered_sender() {
        let (backend, identity) = submitted_activity_backend(MutableRpc::new());
        let exact = observed_transaction_for_identity(&identity);
        let raw = canonical_observed_type_two_bytes(&exact)
            .expect("canonical signed RPC transaction fixture");
        assert_eq!(keccak32(raw.as_slice()), exact.hash);
        assert_eq!(
            recover_signed_type_two_sender(raw.as_slice()).expect("recover exact RPC sender"),
            exact.from
        );

        let mut forged_hash = exact.clone();
        forged_hash.hash[0] ^= 1;
        let mut forged_sender = exact.clone();
        forged_sender.from[0] ^= 1;
        let mut forged_r = exact.clone();
        forged_r.r = Word::from_u64(1);
        let mut forged_s = exact.clone();
        forged_s.s = Word::from_be_bytes([0xff; 32]);
        let mut forged_parity = exact.clone();
        forged_parity.y_parity ^= 1;
        for forged in [
            forged_hash,
            forged_sender,
            forged_r,
            forged_s,
            forged_parity,
        ] {
            assert!(matches!(
                canonical_observed_type_two_bytes(&forged),
                Err(BackendError::ActivityObservationInvalid)
            ));
        }

        let valid_json = rpc_transaction_fixture(&observed_transaction_for_identity(&identity));
        let decoded = rpc::SepoliaRpc::verified_with_single_result(valid_json.clone())
            .transaction_by_hash(rpc::TransactionHash::new(*identity.transaction_hash()))
            .expect("strict JSON transaction fixture")
            .expect("non-null strict JSON transaction fixture");
        assert_eq!(decoded.hash.as_bytes(), identity.transaction_hash());
        let live = LiveRpc(rpc::SepoliaRpc::verified_with_single_result(
            valid_json.clone(),
        ));
        assert!(
            live.activity_transaction(*identity.transaction_hash())
                .expect("valid JSON crosses authenticated LiveRpc bridge")
                .is_some()
        );

        let mut forged_json = Vec::new();
        let mut hash = valid_json.clone();
        hash["hash"] = serde_json::json!(fixed_hex(&[0x11; 32]));
        forged_json.push(hash);
        let mut sender = valid_json.clone();
        sender["from"] = serde_json::json!(fixed_hex(&[0x12; 20]));
        forged_json.push(sender);
        let mut r = valid_json.clone();
        r["r"] = serde_json::json!("0x1");
        forged_json.push(r);
        let mut s = valid_json.clone();
        s["s"] = serde_json::json!(fixed_hex(&[0xff; 32]));
        forged_json.push(s);
        let mut parity = valid_json;
        let opposite = if exact.y_parity == 0 { "0x1" } else { "0x0" };
        parity["v"] = serde_json::json!(opposite);
        parity["yParity"] = serde_json::json!(opposite);
        forged_json.push(parity);
        for forged in forged_json {
            let live = LiveRpc(rpc::SepoliaRpc::verified_with_single_result(forged));
            assert!(
                live.activity_transaction(*identity.transaction_hash())
                    .is_err()
            );
        }
        remove_test_backend_files(&backend);
    }

    fn fill_activity_store_to_capacity(backend: &DemoBackend, sender: [u8; 20]) {
        let context = backend.activity_context().expect("v2 activity context");
        let mut store = ActivityStore::empty(context.vault_id).expect("empty activity store");
        for index in 0..ACTIVITY_CAPACITY {
            let marker = u8::try_from(index + 1).expect("activity capacity marker");
            let identity = TransactionIdentity::native(
                [marker; 32],
                sender,
                0,
                *Word::from_u64(u64::try_from(index).expect("activity nonce index")).as_be_bytes(),
                *Word::from_u64(NATIVE_TRANSFER_GAS).as_be_bytes(),
                *Word::from_u64(1_000_000_000).as_be_bytes(),
                *Word::from_u64(2_000_000_000).as_be_bytes(),
                [0x93; 20],
                *Word::from_u64(1).as_be_bytes(),
            )
            .expect("activity capacity identity");
            store
                .upsert_submitted(&identity)
                .expect("fill activity capacity");
        }
        let sealed = store.seal(&context.key).expect("seal full activity store");
        let activity_lease = ActivityMutationLease::acquire(&backend.activity_store_path)
            .expect("full-store activity mutation lease");
        write_atomic_activity_store(
            &activity_lease,
            &backend.activity_store_path,
            sealed.as_slice(),
        )
        .expect("persist full activity store");
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

    fn snapshot_address(snapshot: &WalletSnapshot) -> &str {
        snapshot
            .selected_account()
            .expect("snapshot must contain its selected account")
            .address
            .as_str()
    }

    fn signed_type_two_fields(raw: &[u8]) -> Vec<Vec<u8>> {
        let (top, consumed) =
            decode_canonical_rlp_item(&raw[1..], 0).expect("decode signed type-two list fixture");
        assert!(top.is_list && consumed == raw.len() - 1);
        let mut fields = Vec::new();
        let mut cursor = 0;
        while cursor < top.payload.len() {
            let (field, next) = decode_canonical_rlp_item(top.payload, cursor)
                .expect("decode signed type-two field fixture");
            fields.push(field.encoded.to_vec());
            cursor = next;
        }
        fields
    }

    fn rebuild_signed_type_two(fields: &[Vec<u8>]) -> Vec<u8> {
        let mut raw = vec![2];
        raw.extend_from_slice(&rlp_list(fields));
        raw
    }

    fn empty_generated_confirmation() -> GeneratedBackupConfirmation {
        GeneratedBackupConfirmation::new(
            std::array::from_fn(|_| SensitiveText::new(String::new())),
            SensitiveText::new(String::new()),
        )
    }

    fn generated_confirmation(
        backend: &DemoBackend,
        wrong_word: bool,
        wrong_address: bool,
    ) -> GeneratedBackupConfirmation {
        let pending = backend
            .pending_generation
            .as_ref()
            .expect("generated confirmation fixture pending");
        let PendingGeneratedStage::Challenge { positions } = &pending.stage else {
            panic!("generated confirmation fixture challenge stage");
        };
        let (_, phrase) = pending
            .wallet
            .export_mnemonic()
            .expect("generated confirmation fixture export")
            .into_zeroizing_text();
        let mut words = positions.map(|position| {
            let word = phrase
                .split(' ')
                .nth(usize::from(position - 1))
                .expect("generated confirmation fixture position");
            SensitiveText::new(word.to_owned())
        });
        if wrong_word {
            words[0] = SensitiveText::new("zzzzzzzz".to_owned());
        }
        let account = pending
            .wallet
            .account(0)
            .expect("generated confirmation fixture account");
        let first_address = if wrong_address {
            "0x0000000000000000000000000000000000000000".to_owned()
        } else {
            checksum_address(*account.address().as_bytes())
        };
        GeneratedBackupConfirmation::new(words, SensitiveText::new(first_address))
    }

    fn begin_challenge_and_confirmation(backend: &mut DemoBackend) -> GeneratedBackupConfirmation {
        backend
            .begin_generated_challenge()
            .expect("begin generated backup challenge");
        generated_confirmation(backend, false, false)
    }

    fn confirm_generated_fixture(
        backend: &mut DemoBackend,
    ) -> Result<WalletSnapshot, BackendError> {
        let confirmation = begin_challenge_and_confirmation(backend);
        let active_epoch = std::sync::atomic::AtomicU64::new(0);
        let permit = SessionPermit::current_for_test(0, &active_epoch);
        backend.confirm_generated(confirmation, &permit)
    }

    fn confirm_without_pending(backend: &mut DemoBackend) -> Result<WalletSnapshot, BackendError> {
        let active_epoch = std::sync::atomic::AtomicU64::new(0);
        let permit = SessionPermit::current_for_test(0, &active_epoch);
        backend.confirm_generated(empty_generated_confirmation(), &permit)
    }

    fn v2_backend(clock: TestClock) -> DemoBackend {
        DemoBackend::with_rpc_and_clock(temporary_vault(), test_rpc(), clock)
    }

    fn import_generated_mnemonic(backend: &mut DemoBackend) -> WalletSnapshot {
        let generated = WalletSecret::generate_mnemonic(MnemonicWordCount::Twelve)
            .expect("generate bounded mnemonic fixture");
        let (_, mut phrase) = generated
            .export_mnemonic()
            .expect("export bounded mnemonic fixture")
            .into_zeroizing_text();
        backend
            .import_mnemonic(
                SensitiveText::new(std::mem::take(&mut *phrase)),
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            )
            .expect("import bounded mnemonic fixture")
    }

    fn token_backend(rpc: TokenRpc, key_marker: u8) -> DemoBackend {
        let mut backend = DemoBackend::with_rpc(temporary_vault(), rpc);
        backend
            .import_private_key(
                sensitive(&fixed_hex(&[key_marker; KEY_BYTES])),
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            )
            .expect("create v2 token test wallet");
        backend
    }

    fn saved_token_backend(rpc: TokenRpc, contract: [u8; 20], key_marker: u8) -> DemoBackend {
        rpc.insert(contract, token_fixture(1));
        let mut backend = token_backend(rpc, key_marker);
        backend
            .add_custom_token_inner(&checksum_address(contract))
            .expect("persist saved token fixture");
        backend
    }

    fn saved_token_backend_with_clock(
        rpc: TokenRpc,
        contract: [u8; 20],
        key_marker: u8,
        clock: TestClock,
    ) -> DemoBackend {
        rpc.insert(contract, token_fixture(1));
        let mut backend = DemoBackend::with_rpc_and_clock(temporary_vault(), rpc, clock);
        backend
            .import_private_key(
                sensitive(&fixed_hex(&[key_marker; KEY_BYTES])),
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            )
            .expect("create v2 timed token test wallet");
        backend
            .add_custom_token_inner(&checksum_address(contract))
            .expect("persist timed saved token fixture");
        backend
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
            let display_deadline = reveal.expires_at();
            drop(reveal);
            let challenge = backend
                .begin_generated_challenge()
                .expect("begin generated backup challenge");
            assert_eq!(challenge.expires_at(), display_deadline);
            let positions = challenge.positions();
            assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(positions.into_iter().all(|position| {
                position >= 1
                    && position
                        <= match words {
                            NewMnemonicWords::Twelve => 12,
                            NewMnemonicWords::TwentyFour => 24,
                        }
            }));
            assert!(!backend.vault_v2_path.exists());
            let confirmation = generated_confirmation(&backend, false, false);
            let active_epoch = std::sync::atomic::AtomicU64::new(0);
            let permit = SessionPermit::current_for_test(0, &active_epoch);
            let snapshot = backend
                .confirm_generated(confirmation, &permit)
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
            assert_eq!(snapshot.accounts.len(), 2);
            assert_eq!(snapshot.selected_account_index, 0);
            assert!(backend.vault_v2_path.is_file());
            assert!(!backend.vault_path.exists());
            assert!(backend.pending_generation.is_none());
            assert!(matches!(backend.unlocked, Some(UnlockedWallet::V2(_))));

            let expected_address = snapshot_address(&snapshot).to_owned();
            backend.lock();
            let reopened = backend.open(TEST_PASSWORD).expect("reopen generated v2");
            assert_eq!(snapshot_address(&reopened), expected_address);
            assert_eq!(reopened.accounts.len(), 2);
            assert_eq!(reopened.selected_account_index, 0);
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
            confirm_without_pending(&mut cancelled),
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
            expired.begin_generated_challenge(),
            Err(BackendError::GenerationExpired)
        ));
        assert!(expired.pending_generation.is_none());
        assert!(!expired.vault_v2_path.exists());
        remove_test_backend_files(&expired);
    }

    #[test]
    fn generated_challenge_selection_is_distinct_sorted_bounded_and_rejection_capped() {
        let mut samples = [11_u8, 10, 9, 8].into_iter();
        let positions = choose_backup_challenge_positions(12, |output| {
            output[0] = samples.next().expect("deterministic challenge sample");
            Ok(())
        })
        .expect("deterministic challenge positions");
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(
            positions
                .into_iter()
                .all(|position| (1..=12).contains(&position))
        );

        let mut calls = 0_usize;
        assert!(matches!(
            choose_backup_challenge_positions(12, |output| {
                calls += 1;
                output[0] = u8::MAX;
                Ok(())
            }),
            Err(BackendError::RandomnessUnavailable)
        ));
        assert_eq!(calls, 256);
    }

    #[test]
    fn generated_challenge_rejection_sampling_has_uniform_accepted_buckets() {
        for bound in [12_u8, 11, 10, 9, 24, 23, 22, 21] {
            let limit = 256_u16 - (256_u16 % u16::from(bound));
            let mut buckets = vec![0_usize; usize::from(bound)];
            for sample in 0_u16..=u16::from(u8::MAX) {
                let mut calls = 0_usize;
                let selected = random_below(bound, &mut |output| {
                    calls += 1;
                    output[0] = if calls == 1 {
                        u8::try_from(sample).expect("sample byte")
                    } else {
                        0
                    };
                    Ok(())
                })
                .expect("bounded rejection sample");
                if sample < limit {
                    buckets[usize::from(selected)] += 1;
                    assert_eq!(calls, 1);
                    assert_eq!(
                        selected,
                        u8::try_from(sample).expect("accepted byte") % bound
                    );
                } else {
                    assert_eq!(selected, 0);
                    assert_eq!(calls, 2);
                }
            }
            let expected =
                usize::from(u8::try_from(limit / u16::from(bound)).expect("bucket count"));
            assert!(buckets.into_iter().all(|count| count == expected));
        }
    }

    #[test]
    fn generated_confirmation_is_one_attempt_for_word_and_address_mismatch() {
        for (wrong_word, wrong_address) in [(true, false), (false, true)] {
            let mut backend = v2_backend(TestClock::new(Instant::now()));
            drop(
                backend
                    .begin_generate(
                        NewMnemonicWords::Twelve,
                        sensitive(TEST_PASSWORD),
                        sensitive(TEST_PASSWORD),
                    )
                    .expect("begin mismatch generation"),
            );
            backend
                .begin_generated_challenge()
                .expect("begin mismatch challenge");
            let confirmation = generated_confirmation(&backend, wrong_word, wrong_address);
            let active_epoch = std::sync::atomic::AtomicU64::new(0);
            let permit = SessionPermit::current_for_test(0, &active_epoch);
            assert!(matches!(
                backend.confirm_generated(confirmation, &permit),
                Err(BackendError::BackupConfirmationFailed)
            ));
            assert!(backend.pending_generation.is_none());
            assert!(!backend.vault_v2_path.exists());
            assert!(matches!(
                confirm_without_pending(&mut backend),
                Err(BackendError::NoPendingGeneration)
            ));
            remove_test_backend_files(&backend);
        }
    }

    #[test]
    fn generated_stage_replay_cancel_and_inclusive_deadline_fail_closed() {
        let mut before_challenge = v2_backend(TestClock::new(Instant::now()));
        drop(
            before_challenge
                .begin_generate(
                    NewMnemonicWords::Twelve,
                    sensitive(TEST_PASSWORD),
                    sensitive(TEST_PASSWORD),
                )
                .expect("begin pre-challenge confirmation"),
        );
        let active_epoch = std::sync::atomic::AtomicU64::new(0);
        let permit = SessionPermit::current_for_test(0, &active_epoch);
        assert!(matches!(
            before_challenge.confirm_generated(empty_generated_confirmation(), &permit),
            Err(BackendError::BackupConfirmationFailed)
        ));
        assert!(before_challenge.pending_generation.is_none());
        assert!(!before_challenge.vault_v2_path.exists());
        remove_test_backend_files(&before_challenge);

        let mut replay = v2_backend(TestClock::new(Instant::now()));
        drop(
            replay
                .begin_generate(
                    NewMnemonicWords::Twelve,
                    sensitive(TEST_PASSWORD),
                    sensitive(TEST_PASSWORD),
                )
                .expect("begin replay generation"),
        );
        replay
            .begin_generated_challenge()
            .expect("begin replay challenge");
        assert!(matches!(
            replay.begin_generated_challenge(),
            Err(BackendError::BackupConfirmationFailed)
        ));
        assert!(replay.pending_generation.is_none());
        assert!(!replay.vault_v2_path.exists());
        remove_test_backend_files(&replay);

        let mut cancelled = v2_backend(TestClock::new(Instant::now()));
        drop(
            cancelled
                .begin_generate(
                    NewMnemonicWords::Twelve,
                    sensitive(TEST_PASSWORD),
                    sensitive(TEST_PASSWORD),
                )
                .expect("begin challenge cancellation"),
        );
        cancelled
            .begin_generated_challenge()
            .expect("begin cancellable challenge");
        cancelled.cancel_generated();
        assert!(cancelled.pending_generation.is_none());
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
                .expect("begin challenge expiry"),
        );
        expired
            .begin_generated_challenge()
            .expect("begin expiring challenge");
        let confirmation = generated_confirmation(&expired, false, false);
        clock.advance(GENERATED_BACKUP_TTL);
        let active_epoch = std::sync::atomic::AtomicU64::new(0);
        let permit = SessionPermit::current_for_test(0, &active_epoch);
        assert!(matches!(
            expired.confirm_generated(confirmation, &permit),
            Err(BackendError::GenerationExpired)
        ));
        assert!(expired.pending_generation.is_none());
        assert!(!expired.vault_v2_path.exists());
        remove_test_backend_files(&expired);
    }

    #[test]
    fn generated_confirmation_rechecks_permit_at_all_five_commit_boundaries() {
        for revoke_on_check in 1..=5 {
            let mut backend = v2_backend(TestClock::new(Instant::now()));
            drop(
                backend
                    .begin_generate(
                        NewMnemonicWords::Twelve,
                        sensitive(TEST_PASSWORD),
                        sensitive(TEST_PASSWORD),
                    )
                    .expect("begin revoked generation"),
            );
            backend
                .begin_generated_challenge()
                .expect("begin revoked challenge");
            let confirmation = generated_confirmation(&backend, false, false);
            let active_epoch = std::sync::atomic::AtomicU64::new(0);
            let permit = SessionPermit::revoke_on_check(0, &active_epoch, revoke_on_check);
            assert!(matches!(
                backend.confirm_generated(confirmation, &permit),
                Err(BackendError::Locked)
            ));
            assert!(backend.pending_generation.is_none());
            assert!(!backend.vault_v2_path.exists());
            assert!(backend.unlocked.is_none());
            remove_test_backend_files(&backend);
        }
    }

    #[test]
    fn generated_confirmation_rechecks_inclusive_deadline_at_all_five_commit_boundaries() {
        for expire_on_call in 3..=7 {
            let clock = ExpireOnCallClock::new(Instant::now(), expire_on_call);
            let mut backend =
                DemoBackend::with_rpc_and_clock(temporary_vault(), test_rpc(), clock.clone());
            drop(
                backend
                    .begin_generate(
                        NewMnemonicWords::Twelve,
                        sensitive(TEST_PASSWORD),
                        sensitive(TEST_PASSWORD),
                    )
                    .expect("begin expiring generation"),
            );
            backend
                .begin_generated_challenge()
                .expect("begin expiring challenge");
            let confirmation = generated_confirmation(&backend, false, false);
            let active_epoch = std::sync::atomic::AtomicU64::new(0);
            let permit = SessionPermit::current_for_test(0, &active_epoch);

            assert!(matches!(
                backend.confirm_generated(confirmation, &permit),
                Err(BackendError::GenerationExpired)
            ));
            assert_eq!(clock.calls(), expire_on_call);
            assert!(backend.pending_generation.is_none());
            assert!(!backend.vault_v2_path.exists());
            assert!(backend.unlocked.is_none());
            remove_test_backend_files(&backend);
        }
    }

    #[test]
    fn generated_confirmation_is_bound_to_its_generation() {
        let mut backend = v2_backend(TestClock::new(Instant::now()));
        drop(
            backend
                .begin_generate(
                    NewMnemonicWords::Twelve,
                    sensitive(TEST_PASSWORD),
                    sensitive(TEST_PASSWORD),
                )
                .expect("begin first generation"),
        );
        backend
            .begin_generated_challenge()
            .expect("begin first challenge");
        let first_confirmation = generated_confirmation(&backend, false, false);
        backend.cancel_generated();

        drop(
            backend
                .begin_generate(
                    NewMnemonicWords::Twelve,
                    sensitive(TEST_PASSWORD),
                    sensitive(TEST_PASSWORD),
                )
                .expect("begin second generation"),
        );
        backend
            .begin_generated_challenge()
            .expect("begin second challenge");
        let active_epoch = std::sync::atomic::AtomicU64::new(0);
        let permit = SessionPermit::current_for_test(0, &active_epoch);

        assert!(matches!(
            backend.confirm_generated(first_confirmation, &permit),
            Err(BackendError::BackupConfirmationFailed)
        ));
        assert!(backend.pending_generation.is_none());
        assert!(!backend.vault_v2_path.exists());
        assert!(backend.unlocked.is_none());
        remove_test_backend_files(&backend);
    }

    #[test]
    fn lock_is_idempotent_drops_session_state_and_preserves_signed_pending_record() {
        let (mut backend, _rpc, _clock) = prepared_mutable_backend();
        let pending_record = b"signed pending preservation sentinel";
        write_new_file(&backend.pending_path, pending_record)
            .expect("write signed pending sentinel");
        assert!(backend.unlocked.is_some());
        assert!(backend.prepared.is_some());
        assert!(backend.last_balance.is_some());

        backend.lock();
        backend.lock();
        assert!(backend.unlocked.is_none());
        assert!(backend.pending_generation.is_none());
        assert!(backend.prepared.is_none());
        assert!(backend.last_balance.is_none());
        assert!(backend.pending_path.is_file());
        assert!(backend.pending_broadcast_exists());
        assert_eq!(
            fs::read(&backend.pending_path).expect("read preserved pending record"),
            pending_record
        );
        assert!(matches!(
            backend.refresh_snapshot(),
            Err(BackendError::Locked)
        ));
        assert!(matches!(
            backend.refresh_custom_tokens_inner(),
            Err(BackendError::Locked)
        ));
        assert!(matches!(
            backend.retry_pending_inner(),
            Err(BackendError::Locked)
        ));
        remove_test_backend_files(&backend);
    }

    #[test]
    fn lock_cancels_unconfirmed_generated_wallet_without_writing_a_vault() {
        let mut backend = v2_backend(TestClock::new(Instant::now()));
        drop(
            backend
                .begin_generate(
                    NewMnemonicWords::Twelve,
                    sensitive(TEST_PASSWORD),
                    sensitive(TEST_PASSWORD),
                )
                .expect("begin generated wallet before lock"),
        );
        assert!(backend.pending_generation.is_some());
        backend.lock();
        assert!(backend.pending_generation.is_none());
        assert!(matches!(
            confirm_without_pending(&mut backend),
            Err(BackendError::NoPendingGeneration)
        ));
        assert!(!backend.vault_v2_path.exists());
        remove_test_backend_files(&backend);
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
        assert_eq!(snapshot.accounts.len(), 2);
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
        assert_eq!(snapshot.accounts.len(), 1);
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
    fn mnemonic_account_switch_is_session_only_and_binds_exports_tokens_and_signers() {
        let native_rpc = MutableRpc::new();
        let token_rpc = TokenRpc::new();
        let contract = [0x6a; 20];
        token_rpc.insert(contract, token_fixture(1));
        let rpc = LifecycleRpc {
            native: native_rpc.clone(),
            tokens: token_rpc.clone(),
        };
        let mut backend = DemoBackend::with_rpc(temporary_vault(), rpc);
        let initial = import_generated_mnemonic(&mut backend);
        let account_zero = initial.accounts[0].address.clone();
        let account_one = initial.accounts[1].address.clone();
        assert!(account_zero != account_one && initial.selected_account_index == 0);
        backend
            .add_custom_token_inner(&checksum_address(contract))
            .expect("persist account-switch token fixture");
        let vault_before = fs::read(&backend.vault_v2_path).expect("read vault before switch");
        let tokens_before =
            fs::read(&backend.token_store_path).expect("read token store before switch");

        let selected = backend
            .select_account_inner(1)
            .expect("select bounded account one");
        assert_eq!(selected.selected_account_index, 1);
        assert_eq!(snapshot_address(&selected), account_one);
        assert_eq!(selected.balance_eth, "조회 전");
        assert!(selected.pending_broadcast.is_none());
        let account_one_bytes = parse_address(&account_one).expect("parse account-one address");
        let refreshed = backend
            .refresh_snapshot()
            .expect("refresh selected account-one native balance");
        assert_eq!(refreshed.selected_account_index, 1);
        assert_eq!(snapshot_address(&refreshed), account_one);
        assert_ne!(refreshed.balance_eth, "조회 전");
        assert_eq!(
            native_rpc
                .state
                .lock()
                .expect("account-one native refresh RPC lock")
                .balance_addresses
                .last()
                .copied(),
            Some(account_one_bytes)
        );
        let refreshed_tokens = backend
            .refresh_custom_tokens_inner()
            .expect("refresh selected account-one token balance");
        assert_eq!(refreshed_tokens.len(), 1);
        assert_eq!(
            token_rpc
                .state
                .lock()
                .expect("account-one token refresh RPC lock")
                .balance_owners
                .last()
                .copied(),
            Some(account_one_bytes)
        );
        assert!(matches!(
            backend.select_account_inner(2),
            Err(BackendError::UnsupportedAccount)
        ));
        assert_eq!(backend.selected_account_index, 1);

        let expected_private_key = match backend.unlocked.as_ref().expect("unlocked mnemonic") {
            UnlockedWallet::V2(opened) => {
                let export = opened
                    .wallet()
                    .export_account_private_key(1)
                    .expect("export expected account-one key");
                let (_, text) = export.into_zeroizing_text();
                text
            }
            UnlockedWallet::LegacyV1 { .. } => panic!("expected v2 mnemonic"),
        };
        let reveal = backend
            .export_account_private_key_inner(sensitive(TEST_PASSWORD))
            .expect("reauthenticate selected account-one export");
        assert_eq!(reveal.account_binding(), Some((1, account_one.as_str())));
        assert_eq!(
            reveal.expose_secret_for_test(),
            expected_private_key.as_str()
        );
        drop(reveal);

        let native = backend
            .prepare_transfer_inner(
                "0x1111111111111111111111111111111111111111",
                "0.25",
                FeeSelection::Recommended,
            )
            .expect("prepare account-one native transfer");
        assert_eq!(native.sender_account_index, 1);
        assert_eq!(native.sender_address, account_one);
        {
            let state = native_rpc
                .state
                .lock()
                .expect("account-one native prepare RPC lock");
            assert_eq!(
                state.pending_balance_addresses.last().copied(),
                Some(account_one_bytes)
            );
            assert_eq!(
                state.estimate_senders.last().copied(),
                Some(account_one_bytes)
            );
        }
        assert!(matches!(
            backend.select_account_inner(0),
            Err(BackendError::AccountSwitchBlocked)
        ));
        assert_eq!(backend.selected_account_index, 1);
        assert_eq!(native_prepared(&backend).account_index, 1);
        backend.cancel_prepared_inner();

        backend
            .prepare_transfer_inner(
                "0x1111111111111111111111111111111111111111",
                "0.25",
                FeeSelection::Recommended,
            )
            .expect("reprepare account-one native transfer");
        backend
            .confirm_prepared_inner()
            .expect("sign exact account-one native transfer");
        assert_eq!(backend.sign_attempts, 1);
        native_rpc.update(|state| state.nonce = Word::from_u64(8));

        let active_epoch = std::sync::atomic::AtomicU64::new(0);
        let permit = SessionPermit::current_for_test(0, &active_epoch);
        let token = backend
            .prepare_saved_erc20_transfer_inner(
                &checksum_address(contract),
                "0x6767676767676767676767676767676767676767",
                "1",
                FeeSelection::Recommended,
                &permit,
            )
            .expect("prepare selected account-one token transfer");
        assert_eq!(token.sender_account_index, 1);
        assert_eq!(token.sender_address, account_one);
        let sign_attempts = backend.sign_attempts;
        backend.selected_account_index = 0;
        assert!(matches!(
            backend.confirm_prepared_with_permit(&permit),
            Err(BackendError::PreparedInvalid)
        ));
        assert_eq!(backend.sign_attempts, sign_attempts);
        backend
            .select_account_inner(1)
            .expect("restore account one after adversarial mutation");
        backend
            .prepare_saved_erc20_transfer_inner(
                &checksum_address(contract),
                "0x6767676767676767676767676767676767676767",
                "1",
                FeeSelection::Recommended,
                &permit,
            )
            .expect("reprepare exact account-one token transfer");
        backend
            .confirm_prepared_with_permit(&permit)
            .expect("sign exact account-one token transfer");
        assert_eq!(backend.sign_attempts, sign_attempts + 1);
        let observation = token_rpc
            .state
            .lock()
            .expect("account-one token RPC lock")
            .preflight_fields
            .last()
            .copied()
            .expect("account-one token preflight");
        assert_eq!(checksum_address(observation.sender), account_one);
        assert_eq!(
            token_rpc
                .state
                .lock()
                .expect("account-one token estimate RPC lock")
                .estimate_senders
                .last()
                .copied(),
            Some(account_one_bytes)
        );
        {
            let state = native_rpc.state.lock().expect("account-one nonce RPC lock");
            assert!(state.nonce_addresses.len() >= 4);
            assert!(
                state
                    .nonce_addresses
                    .iter()
                    .all(|address| *address == account_one_bytes)
            );
        }

        assert_eq!(
            fs::read(&backend.vault_v2_path).expect("read vault after switches"),
            vault_before
        );
        assert_eq!(
            fs::read(&backend.token_store_path).expect("read token store after switches"),
            tokens_before
        );
        backend.lock();
        let reopened = backend
            .open(TEST_PASSWORD)
            .expect("reopen defaults to account zero");
        assert_eq!(reopened.selected_account_index, 0);
        assert_eq!(snapshot_address(&reopened), account_zero);
        remove_test_backend_files(&backend);
    }

    #[test]
    fn raw_and_legacy_wallets_reject_account_one_without_changing_selection() {
        let mut raw = v2_backend(TestClock::new(Instant::now()));
        raw.import_private_key(
            SensitiveText::new("22".repeat(KEY_BYTES)),
            sensitive(TEST_PASSWORD),
            sensitive(TEST_PASSWORD),
        )
        .expect("import raw account-zero fixture");
        assert!(matches!(
            raw.select_account_inner(1),
            Err(BackendError::UnsupportedAccount)
        ));
        assert_eq!(raw.selected_account_index, 0);
        remove_test_backend_files(&raw);

        let mut legacy = DemoBackend::with_rpc(temporary_vault(), test_rpc());
        write_legacy_fixture(&legacy, TEST_PASSWORD, 0x31);
        legacy
            .open(TEST_PASSWORD)
            .expect("open legacy account-zero fixture");
        assert!(matches!(
            legacy.select_account_inner(1),
            Err(BackendError::UnsupportedAccount)
        ));
        assert_eq!(legacy.selected_account_index, 0);
        remove_test_backend_files(&legacy);
    }

    #[test]
    fn account_one_ambiguous_restart_discloses_sender_before_exact_retry() {
        let rpc = MutableRpc::new();
        let vault = temporary_vault();
        let mut backend = DemoBackend::with_rpc(vault.clone(), rpc.clone());
        let initial = import_generated_mnemonic(&mut backend);
        let account_one = initial.accounts[1].address.clone();
        backend.select_account_inner(1).expect("select account one");
        backend
            .prepare_transfer_inner(
                "0x1111111111111111111111111111111111111111",
                "0.25",
                FeeSelection::Recommended,
            )
            .expect("prepare ambiguous account-one transfer");
        rpc.update(|state| state.send_fails = true);
        assert!(matches!(
            backend.confirm_prepared_inner(),
            Err(BackendError::BroadcastUnknown)
        ));
        let exact_raw = rpc
            .state
            .lock()
            .expect("ambiguous account-one RPC lock")
            .sent[0]
            .clone();
        backend.lock();
        drop(backend);

        let mut restarted = DemoBackend::with_rpc(vault, rpc.clone());
        let opened = restarted
            .open(TEST_PASSWORD)
            .expect("reopen and attribute account-one pending");
        assert_eq!(opened.selected_account_index, 0);
        let pending = opened
            .pending_broadcast
            .as_ref()
            .expect("pending attribution is disclosed on open");
        assert_eq!(pending.sender_account_index, 1);
        assert_eq!(pending.sender_address, account_one);
        assert_eq!(pending.transaction_hash, fixed_hex(&keccak32(&exact_raw)));

        restarted.lock();
        assert!(restarted.prepared_pending_retry.is_none());
        assert!(restarted.pending_broadcast_exists());
        let durable = fs::read(&restarted.pending_path).expect("lock releases only the lease");
        assert!(!durable.is_empty());
        let reopened = restarted
            .open(TEST_PASSWORD)
            .expect("reopen creates a fresh exact pending lease");
        assert_eq!(reopened.selected_account_index, 0);
        assert_eq!(
            reopened
                .pending_broadcast
                .as_ref()
                .map(|preview| preview.sender_account_index),
            Some(1)
        );
        rpc.update(|state| state.send_fails = false);
        let epoch = std::sync::atomic::AtomicU64::new(0);
        let permit = SessionPermit::current_for_test(0, &epoch);
        restarted
            .retry_pending_with_permit(&permit)
            .expect("retry frozen account-one bytes");
        assert_eq!(restarted.sign_attempts, 0);
        let state = rpc.state.lock().expect("retried account-one RPC lock");
        assert_eq!(state.sent.len(), 2);
        assert_eq!(state.sent[0], exact_raw);
        assert_eq!(state.sent[1], exact_raw);
        drop(state);
        assert!(!restarted.pending_broadcast_exists());
        remove_test_backend_files(&restarted);
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
        let snapshot = confirm_generated_fixture(&mut backend).expect("persist v2 fixture");
        let legacy_password = "legacy demo password";
        write_legacy_fixture(&backend, legacy_password, 3);
        backend.lock();
        assert!(matches!(
            backend.open(legacy_password),
            Err(BackendError::VaultAuthentication)
        ));
        let reopened = backend.open(TEST_PASSWORD).expect("open preferred v2");
        assert_eq!(snapshot_address(&reopened), snapshot_address(&snapshot));
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
        assert_eq!(snapshot_address(&snapshot), expected);
        assert!(snapshot.wallet_kind == WalletKind::V2RawPrivateKey);
        assert_eq!(snapshot.accounts.len(), 1);
        assert!(backend.vault_v2_path.is_file());
        assert!(!backend.vault_path.exists());
        backend.lock();
        let reopened = backend
            .open("new migration password")
            .expect("open migrated v2");
        assert_eq!(snapshot_address(&reopened), expected);
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
            Err(BackendError::PendingInvalid)
        ));
        assert!(migration.vault_path.is_file());
        assert!(!migration.vault_v2_path.exists());
        remove_test_backend_files(&migration);
    }

    #[test]
    fn legacy_migration_preserves_exact_native_pending_for_v2_restart_retry() {
        let mut backend = v2_backend(TestClock::new(Instant::now()));
        let legacy_key = [0x35_u8; KEY_BYTES];
        let legacy_address = write_legacy_fixture(&backend, TEST_PASSWORD, 0x35);
        let signed = sign_native_type_two(
            &legacy_key,
            legacy_address,
            [0x45; 20],
            Word::from_u64(1_000_000_000_000_000),
            Word::from_u64(7),
            Word::from_u64(NATIVE_TRANSFER_GAS),
            Word::from_u64(1_000_000_000),
            Word::from_u64(2_000_000_000),
        )
        .expect("sign legacy pending migration fixture");
        write_new_pending(
            &backend.pending_path,
            signed.transaction_hash,
            signed.bytes.as_slice(),
        )
        .expect("persist legacy pending migration fixture");
        let exact_raw = signed.bytes.to_vec();

        let snapshot = backend
            .migrate_legacy(
                sensitive(TEST_PASSWORD),
                sensitive("new migration password"),
                sensitive("new migration password"),
            )
            .expect("migrate while preserving exact pending");
        let preview = snapshot
            .pending_broadcast
            .as_ref()
            .expect("migration exposes held pending preview");
        assert_eq!(preview.sender_account_index, 0);
        assert_eq!(preview.sender_address, checksum_address(legacy_address));
        assert_eq!(
            preview.transaction_hash,
            fixed_hex(&signed.transaction_hash)
        );
        let held = backend
            .prepared_pending_retry
            .as_ref()
            .expect("migration transfers pending lease into v2 session");
        assert_eq!(held.transaction_hash, signed.transaction_hash);
        assert_eq!(held.raw_transaction.as_slice(), exact_raw.as_slice());
        assert!(backend.vault_v2_path.is_file());
        assert!(!backend.vault_path.exists());

        let vault_path = backend.vault_path.clone();
        backend.lock();
        let persisted = read_pending(&backend.pending_path)
            .expect("pending remains byte-identical after releasing migration session");
        assert_eq!(persisted.transaction_hash, signed.transaction_hash);
        assert_eq!(persisted.raw_transaction.as_slice(), exact_raw.as_slice());

        let mut restarted = DemoBackend::with_rpc(vault_path, test_rpc());
        restarted
            .open("new migration password")
            .expect("restart opens migrated v2");
        let restart_preview = restarted
            .prepare_pending_retry(None)
            .expect("restart reattributes exact pending under v2");
        assert_eq!(restart_preview.sender_account_index, 0);
        assert_eq!(
            restart_preview.sender_address,
            checksum_address(legacy_address)
        );
        assert_eq!(
            restart_preview.transaction_hash,
            fixed_hex(&signed.transaction_hash)
        );
        restarted.lock();
        remove_test_backend_files(&restarted);
    }

    #[test]
    fn legacy_migration_rejects_foreign_signer_and_valid_erc20_before_v2_write() {
        let mut foreign_backend = v2_backend(TestClock::new(Instant::now()));
        write_legacy_fixture(&foreign_backend, TEST_PASSWORD, 0x41);
        let foreign_key = [0x42_u8; KEY_BYTES];
        let foreign_sender =
            address_from_private_key(&foreign_key).expect("foreign pending sender");
        let foreign = sign_native_type_two(
            &foreign_key,
            foreign_sender,
            [0x43; 20],
            Word::from_u64(1),
            Word::from_u64(7),
            Word::from_u64(NATIVE_TRANSFER_GAS),
            Word::from_u64(1_000_000_000),
            Word::from_u64(2_000_000_000),
        )
        .expect("foreign pending fixture");
        write_new_pending(
            &foreign_backend.pending_path,
            foreign.transaction_hash,
            foreign.bytes.as_slice(),
        )
        .expect("persist foreign pending fixture");
        assert!(matches!(
            foreign_backend.migrate_legacy(
                sensitive(TEST_PASSWORD),
                sensitive("new migration password"),
                sensitive("new migration password"),
            ),
            Err(BackendError::PendingAccountMismatch)
        ));
        assert!(foreign_backend.vault_path.is_file());
        assert!(!foreign_backend.vault_v2_path.exists());
        assert!(foreign_backend.pending_broadcast_exists());
        remove_test_backend_files(&foreign_backend);

        let mut token_backend = v2_backend(TestClock::new(Instant::now()));
        let legacy_key = [0x44_u8; KEY_BYTES];
        let legacy_sender = write_legacy_fixture(&token_backend, TEST_PASSWORD, 0x44);
        let token = sign_erc20_type_two(
            &legacy_key,
            legacy_sender,
            [0x45; 20],
            [0x46; 20],
            TokenAmount::from_be_bytes(*Word::from_u64(10).as_be_bytes()),
            Word::from_u64(7),
            Word::from_u64(60_000),
            Word::from_u64(1_000_000_000),
            Word::from_u64(2_000_000_000),
        )
        .expect("valid legacy-signed ERC20 pending fixture");
        write_new_pending(
            &token_backend.pending_path,
            token.transaction_hash,
            token.bytes.as_slice(),
        )
        .expect("persist legacy ERC20 pending fixture");
        assert!(matches!(
            token_backend.migrate_legacy(
                sensitive(TEST_PASSWORD),
                sensitive("new migration password"),
                sensitive("new migration password"),
            ),
            Err(BackendError::PendingInvalid)
        ));
        assert!(token_backend.vault_path.is_file());
        assert!(!token_backend.vault_v2_path.exists());
        assert!(token_backend.pending_broadcast_exists());
        remove_test_backend_files(&token_backend);
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
        assert!(snapshot_address(&created).starts_with("0x"));
        assert_eq!(created.balance_eth, "0");
        assert!(matches!(
            backend.create(TEST_PASSWORD),
            Err(BackendError::AlreadyExists)
        ));
        backend.lock();
        let reopened = backend.open(TEST_PASSWORD).expect("reopen wallet");
        assert_eq!(snapshot_address(&reopened), snapshot_address(&created));
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
        let created = backend
            .import_private_key(
                sensitive(&fixed_hex(&[7_u8; KEY_BYTES])),
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            )
            .expect("create v2 wallet");
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

        let prepared = native_prepared(&backend);
        let expected = sign_native_type_two(
            &[7_u8; KEY_BYTES],
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
        assert_eq!(
            backend.address().as_deref(),
            Some(snapshot_address(&created))
        );
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
        assert!(native_prepared(&faster).priority_fee == Word::from_u64(2_000_000_000));
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
    fn headless_real_backend_lifecycle_persists_reopens_exports_tokens_and_sends() {
        let native = MutableRpc::new();
        let tokens = TokenRpc::new();
        let contract = [0x41; 20];
        tokens.insert(contract, token_fixture(1));
        let rpc = LifecycleRpc {
            native: native.clone(),
            tokens,
        };
        let clock = TestClock::new(Instant::now());
        let vault_path = temporary_vault();
        let imported_key = [0x2a; KEY_BYTES];
        let expected_address = checksum_address(
            address_from_private_key(&imported_key).expect("derive imported account zero"),
        );

        let mut imported =
            DemoBackend::with_rpc_and_clock(vault_path.clone(), rpc.clone(), clock.clone());
        let imported_snapshot = imported
            .import_private_key(
                sensitive(&fixed_hex(&imported_key)),
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            )
            .expect("import and persist known v2 account zero");
        assert!(snapshot_address(&imported_snapshot) == expected_address);
        assert!(imported_snapshot.wallet_kind == WalletKind::V2RawPrivateKey);
        assert_eq!(imported_snapshot.accounts.len(), 1);
        assert!(imported.vault_v2_path.is_file());
        assert!(!path_may_exist(&imported.vault_path));
        let persisted_vault = fs::read(&imported.vault_v2_path).expect("read persisted v2 vault");
        assert!(!persisted_vault.is_empty());
        drop(imported);

        let mut restarted =
            DemoBackend::with_rpc_and_clock(vault_path.clone(), rpc.clone(), clock.clone());
        assert!(matches!(
            restarted.open("incorrect demo password"),
            Err(BackendError::VaultAuthentication)
        ));
        assert!(restarted.unlocked.is_none());
        assert!(
            fs::read(&restarted.vault_v2_path).expect("reread v2 vault after rejected password")
                == persisted_vault
        );

        let reopened_snapshot = restarted
            .open(TEST_PASSWORD)
            .expect("reopen persisted v2 wallet");
        assert!(snapshot_address(&reopened_snapshot) == expected_address);
        let account_zero_export = restarted
            .export_account_private_key_inner(sensitive(TEST_PASSWORD))
            .expect("reauthenticate and export account zero");
        drop(account_zero_export);
        let UnlockedWallet::V2(opened) = restarted
            .unlocked
            .as_ref()
            .expect("v2 wallet remains unlocked after export")
        else {
            panic!("expected imported v2 wallet");
        };
        let account_zero = opened
            .wallet()
            .account_private_key(0)
            .expect("load imported account zero");
        assert!(account_zero.as_bytes() == &imported_key);
        drop(account_zero);
        let exact_export = opened
            .wallet()
            .export_account_private_key(0)
            .expect("export exact account zero from reopened wallet");
        let (export_kind, export_text) = exact_export.into_zeroizing_text();
        assert!(export_kind == SecretExportKind::AccountPrivateKey);
        assert!(export_text.as_str() == hex_without_prefix(&imported_key));
        drop(export_text);

        let contract_text = checksum_address(contract);
        let added = restarted
            .add_custom_token_inner(&contract_text)
            .expect("validate and persist custom token");
        assert_eq!(added.len(), 1);
        assert!(added[0].contract_address == contract_text);
        assert!(matches!(
            &added[0].state,
            CustomTokenState::Verified {
                symbol,
                decimals,
                balance,
            } if symbol.as_deref() == Some("TOK") && *decimals == 2 && balance == "12.35"
        ));
        assert!(restarted.token_store_path.is_file());
        assert!(
            !fs::read(&restarted.token_store_path)
                .expect("read persisted authenticated token store")
                .is_empty()
        );
        drop(restarted);

        let mut final_restart = DemoBackend::with_rpc_and_clock(vault_path, rpc, clock.clone());
        let final_snapshot = final_restart
            .open(TEST_PASSWORD)
            .expect("reopen wallet and authenticated token sidecar");
        assert!(snapshot_address(&final_snapshot) == expected_address);
        let refreshed = final_restart
            .refresh_custom_tokens_inner()
            .expect("refresh persisted token after process restart");
        assert!(refreshed == added);

        let recipient = "0x1111111111111111111111111111111111111111";
        let preview = final_restart
            .prepare_transfer_inner(
                recipient,
                "0.25",
                FeeSelection::Custom {
                    max_priority_fee_per_gas_gwei: "1.25".to_owned(),
                    max_fee_per_gas_gwei: "3.5".to_owned(),
                },
            )
            .expect("prepare exact custom-fee native transfer");
        assert_eq!(preview.max_priority_fee_per_gas_gwei, "1.25");
        assert_eq!(preview.max_fee_per_gas_gwei, "3.5");
        assert_eq!(preview.gas_limit, NATIVE_TRANSFER_GAS.to_string());
        let pending_path = final_restart.pending_path.clone();
        native.update(|state| {
            state.pending_path_to_require = Some(pending_path);
            state.send_observed_pending = false;
            state.send_observed_exact_pending = false;
        });

        let receipt = final_restart
            .confirm_prepared_inner()
            .expect("sign, durably stage, and verify mock broadcast");
        assert_eq!(final_restart.sign_attempts, 1);
        let expected_transaction_hash = {
            let state = native.state.lock().expect("lifecycle native RPC lock");
            assert_eq!(state.sent.len(), 1);
            assert!(state.send_observed_pending);
            assert!(state.send_observed_exact_pending);
            keccak32(&state.sent[0])
        };
        assert!(receipt.transaction_hash == fixed_hex(&expected_transaction_hash));
        assert!(!final_restart.pending_broadcast_exists());
        assert!(!path_may_exist(&final_restart.pending_path));

        let v2_path = final_restart.vault_v2_path.clone();
        drop(final_restart);
        let mut corrupted_bytes = fs::read(&v2_path).expect("read v2 vault for corruption probe");
        let last = corrupted_bytes
            .len()
            .checked_sub(1)
            .expect("v2 vault is nonempty");
        corrupted_bytes[last] ^= 1;
        fs::write(&v2_path, corrupted_bytes).expect("install corrupted v2 fixture");

        let mut corrupted = DemoBackend::with_rpc_and_clock(
            v2_path.with_file_name("vault-v1.bin"),
            LifecycleRpc {
                native,
                tokens: TokenRpc::new(),
            },
            clock,
        );
        assert!(matches!(
            corrupted.open(TEST_PASSWORD),
            Err(BackendError::VaultAuthentication)
        ));
        assert!(corrupted.unlocked.is_none());
        remove_test_backend_files(&corrupted);
    }

    #[test]
    fn custom_tokens_add_refresh_remove_and_restart_with_authenticated_sidecar() {
        let rpc = TokenRpc::new();
        let contract = [0x11; 20];
        rpc.insert(contract, token_fixture(1));
        let mut backend = token_backend(rpc.clone(), 7);
        let vault_path = backend.vault_path.clone();
        let contract_text = checksum_address(contract);

        let added = backend
            .add_custom_token_inner(&contract_text)
            .expect("add validated token");
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].contract_address, contract_text);
        match &added[0].state {
            CustomTokenState::Verified {
                symbol,
                decimals,
                balance,
            } => {
                assert_eq!(symbol.as_deref(), Some("TOK"));
                assert_eq!(*decimals, 2);
                assert_eq!(balance, "12.35");
            }
            CustomTokenState::Unavailable { .. } => panic!("token unexpectedly unavailable"),
        }
        assert!(backend.token_store_path.is_file());
        assert!(!path_may_exist(
            &token_store_temporary_path(&backend.token_store_path).expect("temporary path")
        ));

        let mut restarted = DemoBackend::with_rpc(vault_path.clone(), rpc.clone());
        restarted
            .open(TEST_PASSWORD)
            .expect("reopen exact v2 wallet");
        let refreshed = restarted
            .refresh_custom_tokens_inner()
            .expect("refresh authenticated token store");
        assert_eq!(refreshed.len(), 1);
        assert_eq!(refreshed[0].contract_address, contract_text);

        let removed = restarted
            .remove_custom_token_inner(&contract_text)
            .expect("remove exact token");
        assert!(removed.is_empty());
        let context = restarted.token_context().expect("v2 token context");
        let empty = restarted
            .load_token_store(&context)
            .expect("authenticated empty store");
        assert!(empty.store.entries().is_empty());
        assert_eq!(empty.store.generation(), 2);

        let mut second_restart = DemoBackend::with_rpc(vault_path, rpc);
        second_restart
            .open(TEST_PASSWORD)
            .expect("reopen after removal");
        assert!(
            second_restart
                .refresh_custom_tokens_inner()
                .expect("refresh empty store after restart")
                .is_empty()
        );
        remove_test_backend_files(&second_restart);
    }

    #[test]
    fn token_store_tamper_wrong_vault_and_rollback_behavior_are_explicit() {
        let rpc = TokenRpc::new();
        let first_contract = [0x21; 20];
        let second_contract = [0x22; 20];
        rpc.insert(first_contract, token_fixture(1));
        rpc.insert(second_contract, token_fixture(2));
        let mut backend = token_backend(rpc.clone(), 7);
        backend
            .add_custom_token_inner(&checksum_address(first_contract))
            .expect("add first token");
        let generation_one = fs::read(&backend.token_store_path).expect("read generation one");

        let mut tampered = generation_one.clone();
        let last = tampered.last_mut().expect("nonempty store");
        *last ^= 1;
        fs::write(&backend.token_store_path, &tampered).expect("tamper token fixture");
        assert!(matches!(
            backend.refresh_custom_tokens_inner(),
            Err(BackendError::TokenStoreInvalid)
        ));
        assert!(matches!(
            backend.add_custom_token_inner(&checksum_address(second_contract)),
            Err(BackendError::TokenStoreInvalid)
        ));
        assert_eq!(
            fs::read(&backend.token_store_path).expect("read refused overwrite"),
            tampered
        );
        fs::write(&backend.token_store_path, &generation_one).expect("restore valid store");

        let mut other = token_backend(rpc.clone(), 8);
        let other_store_path = other.token_store_path.clone();
        other.token_store_path = backend.token_store_path.clone();
        assert!(matches!(
            other.refresh_custom_tokens_inner(),
            Err(BackendError::TokenStoreInvalid)
        ));
        other.token_store_path = other_store_path;

        backend
            .add_custom_token_inner(&checksum_address(second_contract))
            .expect("advance token-store generation");
        fs::write(&backend.token_store_path, &generation_one)
            .expect("simulate authenticated rollback");
        let rolled_back = backend
            .refresh_custom_tokens_inner()
            .expect("generation is consistency-only, not an external rollback anchor");
        assert_eq!(rolled_back.len(), 1);
        assert_eq!(
            rolled_back[0].contract_address,
            checksum_address(first_contract)
        );
        assert!(matches!(
            rolled_back[0].state,
            CustomTokenState::Verified { .. }
        ));

        remove_test_backend_files(&other);
        remove_test_backend_files(&backend);
    }

    #[test]
    fn saved_token_runtime_drift_omits_all_metadata_and_balance() {
        let rpc = TokenRpc::new();
        let contract = [0x31; 20];
        rpc.insert(contract, token_fixture(1));
        let mut backend = token_backend(rpc.clone(), 7);
        backend
            .add_custom_token_inner(&checksum_address(contract))
            .expect("add stable token");

        let assert_unavailable = |backend: &DemoBackend, expected: BackendError| {
            let views = backend
                .refresh_custom_tokens_inner()
                .expect("store itself remains authenticated");
            assert_eq!(views.len(), 1);
            assert_eq!(views[0].contract_address, checksum_address(contract));
            match &views[0].state {
                CustomTokenState::Unavailable { reason_ko } => {
                    assert_eq!(reason_ko, &error_text(expected));
                }
                CustomTokenState::Verified { .. } => panic!("drifted token remained trusted"),
            }
        };

        rpc.update(|state| {
            state
                .contracts
                .get_mut(&contract)
                .expect("fixture")
                .code
                .push(1);
        });
        assert_unavailable(&backend, BackendError::TokenCodeChanged);

        rpc.insert(contract, token_fixture(1));
        rpc.update(|state| {
            state
                .contracts
                .get_mut(&contract)
                .expect("fixture")
                .decimals = abi_u8(3);
        });
        assert_unavailable(&backend, BackendError::TokenMetadataChanged);

        rpc.insert(contract, token_fixture(1));
        rpc.update(|state| {
            state.contracts.get_mut(&contract).expect("fixture").symbol = abi_symbol("NEW");
        });
        assert_unavailable(&backend, BackendError::TokenMetadataChanged);

        rpc.insert(contract, token_fixture(1));
        rpc.update(|state| {
            state.contracts.get_mut(&contract).expect("fixture").balance = vec![0; 31];
        });
        assert_unavailable(&backend, BackendError::TokenMetadataInvalid);

        rpc.update(|state| state.query_fails = true);
        assert_unavailable(&backend, BackendError::TokenQueryUnavailable);
        remove_test_backend_files(&backend);
    }

    #[test]
    fn token_contract_input_empty_code_duplicate_and_capacity_fail_closed() {
        let rpc = TokenRpc::new();
        let empty_contract = [0x41; 20];
        let valid_contract = [0x42; 20];
        let mut empty = token_fixture(1);
        empty.code.clear();
        rpc.insert(empty_contract, empty);
        rpc.insert(valid_contract, token_fixture(2));
        let mut backend = token_backend(rpc.clone(), 7);

        for invalid in [
            "",
            "0X4242424242424242424242424242424242424242",
            "4242424242424242424242424242424242424242",
            "0x0000000000000000000000000000000000000000",
            "0x424242424242424242424242424242424242424g",
        ] {
            assert!(matches!(
                backend.add_custom_token_inner(invalid),
                Err(BackendError::TokenContractAddressInvalid)
            ));
        }
        let mut bad_checksum = checksum_address([0xab; 20]);
        let index = bad_checksum
            .bytes()
            .enumerate()
            .skip(2)
            .find(|(_, byte)| byte.is_ascii_alphabetic())
            .map(|(index, _)| index)
            .expect("checksummed address has a letter");
        let replacement = if bad_checksum.as_bytes()[index].is_ascii_lowercase() {
            bad_checksum.as_bytes()[index].to_ascii_uppercase()
        } else {
            bad_checksum.as_bytes()[index].to_ascii_lowercase()
        };
        // SAFETY: replacement remains one ASCII hexadecimal byte.
        unsafe { bad_checksum.as_bytes_mut()[index] = replacement };
        assert!(matches!(
            backend.add_custom_token_inner(&bad_checksum),
            Err(BackendError::TokenContractAddressInvalid)
        ));

        assert!(matches!(
            backend.add_custom_token_inner(&checksum_address(empty_contract)),
            Err(BackendError::TokenContractEmpty)
        ));
        backend
            .add_custom_token_inner(&checksum_address(valid_contract))
            .expect("add valid token");
        assert!(matches!(
            backend.add_custom_token_inner(&checksum_address(valid_contract)),
            Err(BackendError::TokenDuplicate)
        ));

        let context = backend.token_context().expect("v2 context");
        let mut full = TokenStore::empty(context.vault_id).expect("empty token store");
        for marker in 1_u8..=32 {
            let mut contract = [marker; 20];
            contract[0] = 0x55;
            full.add(
                TokenEntry::new(contract, 2, Some("TOK".to_owned()), [marker; 32])
                    .expect("valid capacity entry"),
            )
            .expect("fill capacity");
        }
        let full_bytes = full.seal(&context.key).expect("seal full fixture");
        write_atomic_token_store(&backend.token_store_path, full_bytes.as_slice())
            .expect("install full fixture");
        let overflow_contract = [0x77; 20];
        rpc.insert(overflow_contract, token_fixture(3));
        assert!(matches!(
            backend.add_custom_token_inner(&checksum_address(overflow_contract)),
            Err(BackendError::TokenCapacity)
        ));
        remove_test_backend_files(&backend);
    }

    #[test]
    fn token_store_exact_bytes_and_generation_form_one_step_cas() {
        let rpc = TokenRpc::new();
        let first_contract = [0x71; 20];
        let second_contract = [0x72; 20];
        rpc.insert(first_contract, token_fixture(1));
        rpc.insert(second_contract, token_fixture(2));
        let mut backend = token_backend(rpc, 7);
        backend
            .add_custom_token_inner(&checksum_address(first_contract))
            .expect("create generation one");

        let context = backend.token_context().expect("v2 token context");
        let mut loaded = backend
            .load_token_store(&context)
            .expect("capture exact generation-one baseline");
        assert_eq!(loaded.baseline.generation, 1);
        let baseline_bytes = loaded
            .baseline
            .bytes
            .as_ref()
            .expect("existing baseline")
            .clone();
        loaded
            .store
            .add(
                TokenEntry::new(second_contract, 2, Some("TOK".to_owned()), [2; 32])
                    .expect("second entry"),
            )
            .expect("advance exactly once");

        // Re-sealing the same authenticated state gives a distinct byte string
        // with the same generation. Exact-byte CAS must still reject it.
        let same_state =
            TokenStore::open(baseline_bytes.as_slice(), &context.key, &context.vault_id)
                .expect("open baseline for alternate sealing");
        let alternate_bytes = same_state
            .seal(&context.key)
            .expect("seal same logical generation with a fresh nonce");
        assert_ne!(alternate_bytes, baseline_bytes);
        write_atomic_token_store(&backend.token_store_path, alternate_bytes.as_slice())
            .expect("install same-generation competing bytes");
        assert!(matches!(
            backend.persist_token_store(&context, &loaded.store, &loaded.baseline),
            Err(BackendError::TokenStoreChanged)
        ));
        assert_eq!(
            fs::read(&backend.token_store_path).expect("read competing bytes"),
            alternate_bytes
        );

        // Restoring the exact baseline makes the one-step mutation valid.
        write_atomic_token_store(&backend.token_store_path, baseline_bytes.as_slice())
            .expect("restore exact baseline");
        backend
            .persist_token_store(&context, &loaded.store, &loaded.baseline)
            .expect("commit exact baseline plus one generation");
        let generation_two = fs::read(&backend.token_store_path).expect("read generation two");

        // A caller may not batch two logical mutations behind one captured
        // baseline even if the resulting store is otherwise authenticated.
        let mut skipped = backend
            .load_token_store(&context)
            .expect("capture generation two");
        skipped
            .store
            .add(
                TokenEntry::new([0x73; 20], 2, Some("TOK".to_owned()), [3; 32])
                    .expect("third entry"),
            )
            .expect("advance to generation three");
        skipped
            .store
            .add(
                TokenEntry::new([0x74; 20], 2, Some("TOK".to_owned()), [4; 32])
                    .expect("fourth entry"),
            )
            .expect("skip to generation four");
        assert!(matches!(
            backend.persist_token_store(&context, &skipped.store, &skipped.baseline),
            Err(BackendError::TokenStoreInvalid)
        ));
        assert_eq!(
            fs::read(&backend.token_store_path).expect("read unchanged generation two"),
            generation_two
        );
        remove_test_backend_files(&backend);
    }

    #[test]
    fn token_add_rejects_code_or_metadata_drift_during_one_inspection() {
        let rpc = TokenRpc::new();
        let contract = [0x75; 20];
        rpc.insert(contract, token_fixture(1));
        let mut backend = token_backend(rpc.clone(), 7);

        let mut upgraded = token_fixture(1);
        upgraded.code.push(0x01);
        rpc.update(|state| {
            state.query_calls = 0;
            state.replace_on_query = Some((5, contract, upgraded));
        });
        assert!(matches!(
            backend.add_custom_token_inner(&checksum_address(contract)),
            Err(BackendError::TokenCodeChanged)
        ));
        assert!(!path_may_exist(&backend.token_store_path));

        rpc.insert(contract, token_fixture(1));
        let mut changed_metadata = token_fixture(1);
        changed_metadata.decimals = abi_u8(3);
        rpc.update(|state| {
            state.query_calls = 0;
            state.replace_on_query = Some((6, contract, changed_metadata));
        });
        assert!(matches!(
            backend.add_custom_token_inner(&checksum_address(contract)),
            Err(BackendError::TokenMetadataChanged)
        ));
        assert!(!path_may_exist(&backend.token_store_path));
        remove_test_backend_files(&backend);
    }

    #[test]
    fn token_add_rechecks_chain_identity_after_contract_reads() {
        let rpc = TokenRpc::new();
        let contract = [0x76; 20];
        rpc.insert(contract, token_fixture(1));
        rpc.update(|state| {
            state.verify_calls = 0;
            // add gate, inspection start, inspection end
            state.fail_verify_on_call = Some(3);
        });
        let mut backend = token_backend(rpc, 7);
        assert!(matches!(
            backend.add_custom_token_inner(&checksum_address(contract)),
            Err(BackendError::RpcUnavailable)
        ));
        assert!(!path_may_exist(&backend.token_store_path));
        remove_test_backend_files(&backend);
    }

    #[test]
    fn token_store_nonregular_path_and_atomic_temp_failure_never_overwrite() {
        let rpc = TokenRpc::new();
        let first_contract = [0x51; 20];
        let second_contract = [0x52; 20];
        rpc.insert(first_contract, token_fixture(1));
        rpc.insert(second_contract, token_fixture(2));
        let mut backend = token_backend(rpc, 7);

        fs::create_dir(&backend.token_store_path).expect("create nonregular token path");
        assert!(matches!(
            backend.refresh_custom_tokens_inner(),
            Err(BackendError::TokenStoreInvalid)
        ));
        assert!(matches!(
            backend.add_custom_token_inner(&checksum_address(first_contract)),
            Err(BackendError::TokenStoreInvalid)
        ));
        assert!(backend.token_store_path.is_dir());
        fs::remove_dir(&backend.token_store_path).expect("remove nonregular token path");

        backend
            .add_custom_token_inner(&checksum_address(first_contract))
            .expect("create first atomic store");
        let committed = fs::read(&backend.token_store_path).expect("read committed store");
        let temporary =
            token_store_temporary_path(&backend.token_store_path).expect("temporary path");
        fs::create_dir(&temporary).expect("block atomic temporary name");
        assert!(matches!(
            backend.add_custom_token_inner(&checksum_address(second_contract)),
            Err(BackendError::TokenStoreStorage)
        ));
        assert_eq!(
            fs::read(&backend.token_store_path).expect("read unchanged store"),
            committed
        );
        assert!(temporary.is_dir());
        remove_test_backend_files(&backend);
    }

    #[test]
    fn token_store_atomic_replace_has_exact_temp_and_installed_readback() {
        let root = temporary_vault()
            .parent()
            .expect("temporary test parent")
            .to_path_buf();
        fs::create_dir_all(&root).expect("create atomic-readback directory");
        let path = root.join("tokens-v1.bin");
        let first = vec![0x11; 128];
        let second = vec![0x22; 128];

        write_atomic_token_store(&path, first.as_slice()).expect("first atomic install");
        assert_eq!(
            verify_exact_token_store_readback(&path, first.as_slice())
                .expect("verify first installed bytes"),
            first
        );
        write_atomic_token_store(&path, second.as_slice()).expect("atomic replacement");
        assert_eq!(
            verify_exact_token_store_readback(&path, second.as_slice())
                .expect("verify replacement bytes"),
            second
        );
        assert!(!path_may_exist(
            &token_store_temporary_path(&path).expect("temporary path")
        ));

        let mut corrupted = second.clone();
        corrupted[0] ^= 1;
        fs::write(&path, &corrupted).expect("simulate post-install corruption");
        assert!(matches!(
            verify_exact_token_store_readback(&path, second.as_slice()),
            Err(BackendError::TokenStoreStorage)
        ));
        assert_eq!(
            fs::read(&path).expect("read detected corruption"),
            corrupted
        );

        let _ = fs::remove_file(path);
        let _ = fs::remove_dir(root);
    }

    #[test]
    fn token_store_cas_rejects_competing_creation_or_deletion() {
        let vault = temporary_vault();
        let root = vault.parent().expect("temporary test parent").to_path_buf();
        fs::create_dir_all(&root).expect("create CAS directory");
        let backend = DemoBackend::with_rpc(vault, test_rpc());
        let context = TokenContext {
            account_index: 0,
            owner: [1; 20],
            vault_id: [2; 16],
            key: Zeroizing::new([3; 32]),
        };

        let mut creation_candidate =
            TokenStore::empty(context.vault_id).expect("empty creation candidate");
        creation_candidate
            .add(TokenEntry::new([4; 20], 2, None, [5; 32]).expect("creation candidate entry"))
            .expect("generation one candidate");
        let absent = TokenStoreBaseline {
            bytes: None,
            generation: 0,
        };
        fs::write(&backend.token_store_path, b"competing creator")
            .expect("install competing creation");
        assert!(matches!(
            backend.persist_token_store(&context, &creation_candidate, &absent),
            Err(BackendError::TokenStoreChanged)
        ));
        assert_eq!(
            fs::read(&backend.token_store_path).expect("competing creation preserved"),
            b"competing creator"
        );

        fs::remove_file(&backend.token_store_path).expect("remove competing creation");
        let generation_one = creation_candidate
            .seal(&context.key)
            .expect("seal generation-one baseline");
        write_atomic_token_store(&backend.token_store_path, generation_one.as_slice())
            .expect("install generation-one baseline");
        let mut loaded = backend
            .load_token_store(&context)
            .expect("capture existing baseline");
        loaded
            .store
            .add(TokenEntry::new([6; 20], 2, None, [7; 32]).expect("deletion-race entry"))
            .expect("advance to generation two");
        fs::remove_file(&backend.token_store_path).expect("simulate competing deletion");
        assert!(matches!(
            backend.persist_token_store(&context, &loaded.store, &loaded.baseline),
            Err(BackendError::TokenStoreChanged)
        ));
        assert!(!path_may_exist(&backend.token_store_path));
        remove_test_backend_files(&backend);
    }

    #[cfg(windows)]
    #[test]
    fn windows_token_lock_is_exclusive_persistent_and_not_a_stale_marker() {
        use std::os::windows::fs::OpenOptionsExt;

        let vault = temporary_vault();
        let root = vault.parent().expect("temporary test parent").to_path_buf();
        fs::create_dir_all(&root).expect("create lock-test directory");
        let token_path = root.join("tokens-v1.bin");
        let lock_path = token_store_lock_path(&token_path).expect("lock path");

        // A previous process may have crashed after creating the persistent
        // empty inode. The absence of an owning handle means it is immediately
        // reusable and must never be interpreted as a stale lock marker.
        File::create(&lock_path).expect("create prior empty lock marker");
        let first = TokenMutationLease::acquire(&token_path)
            .expect("acquire pre-existing persistent lock file");
        let metadata = fs::symlink_metadata(&lock_path).expect("lock metadata");
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.len(), 0);

        let competing = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&lock_path);
        assert!(
            competing.is_err(),
            "exclusive lease allowed a second handle"
        );
        drop(first);

        let second = TokenMutationLease::acquire(&token_path)
            .expect("reacquire immediately after prior owner exits");
        drop(second);
        assert!(lock_path.is_file(), "persistent lock inode disappeared");
        assert_eq!(
            fs::metadata(&lock_path)
                .expect("persistent lock metadata")
                .len(),
            0
        );

        fs::write(&lock_path, b"not an ownership token").expect("corrupt lock record");
        assert!(matches!(
            TokenMutationLease::acquire(&token_path),
            Err(BackendError::TokenStoreInvalid)
        ));
        let _ = fs::remove_file(lock_path);
        let _ = fs::remove_dir(root);
    }

    #[cfg(windows)]
    #[test]
    fn windows_activity_lock_and_temp_are_exclusive_reparse_safe_and_recoverable() {
        use std::os::windows::fs::{OpenOptionsExt, symlink_file};

        let backend = DemoBackend::with_rpc(temporary_vault(), test_rpc());
        let parent = backend
            .activity_store_path
            .parent()
            .expect("activity test parent");
        fs::create_dir_all(parent).expect("create activity lock-test parent");
        let lock_path =
            activity_store_lock_path(&backend.activity_store_path).expect("activity lock path");
        let temporary = activity_store_temporary_path(&backend.activity_store_path)
            .expect("activity temporary path");

        File::create(&lock_path).expect("create prior empty activity lock marker");
        let first = ActivityMutationLease::acquire(&backend.activity_store_path)
            .expect("acquire pre-existing activity lock");
        let competing = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&lock_path);
        assert!(
            competing.is_err(),
            "activity lock allowed a competing handle"
        );
        drop(first);
        let second = ActivityMutationLease::acquire(&backend.activity_store_path)
            .expect("reacquire activity lock after owner exits");
        drop(second);

        fs::write(&lock_path, b"corrupt activity lock").expect("corrupt activity lock fixture");
        assert!(matches!(
            ActivityMutationLease::acquire(&backend.activity_store_path),
            Err(BackendError::ActivityStoreInvalid)
        ));
        fs::remove_file(&lock_path).expect("remove corrupt activity lock fixture");

        let lock_target = parent.join("activity-lock-reparse-target");
        fs::write(&lock_target, b"lock target").expect("write activity lock reparse target");
        if symlink_file(&lock_target, &lock_path).is_ok() {
            assert!(matches!(
                ActivityMutationLease::acquire(&backend.activity_store_path),
                Err(BackendError::ActivityStoreInvalid)
            ));
            assert_eq!(
                fs::read(&lock_target).expect("activity lock target survives"),
                b"lock target"
            );
            fs::remove_file(&lock_path).expect("remove activity lock reparse fixture");
        }

        let temp_target = parent.join("activity-temp-reparse-target");
        fs::write(&temp_target, b"temp target").expect("write activity temp reparse target");
        if symlink_file(&temp_target, &temporary).is_ok() {
            assert!(matches!(
                ActivityMutationLease::acquire(&backend.activity_store_path),
                Err(BackendError::ActivityStoreInvalid | BackendError::ActivityStoreStorage)
            ));
            assert_eq!(
                fs::read(&temp_target).expect("activity temp target survives"),
                b"temp target"
            );
            fs::remove_file(&temporary).expect("remove activity temp reparse fixture");
        }

        fs::write(&temporary, b"regular crash orphan")
            .expect("write regular activity orphan fixture");
        let recovered = ActivityMutationLease::acquire(&backend.activity_store_path)
            .expect("reconcile exact regular activity orphan");
        assert!(!path_may_exist(&temporary));
        drop(recovered);

        remove_test_backend_files(&backend);
        let _ = fs::remove_file(lock_target);
        let _ = fs::remove_file(temp_target);
    }

    #[test]
    fn token_mutations_block_pending_prepared_and_legacy_wallets() {
        let rpc = TokenRpc::new();
        let contract = [0x61; 20];
        rpc.insert(contract, token_fixture(1));
        let mut backend = token_backend(rpc, 7);
        write_new_file(&backend.pending_path, b"pending marker").expect("pending fixture");
        assert!(matches!(
            backend.add_custom_token_inner(&checksum_address(contract)),
            Err(BackendError::PendingExists)
        ));
        fs::remove_file(&backend.pending_path).expect("remove pending fixture");

        backend.prepared = Some(PreparedTransfer::Native(PreparedNativeTransfer {
            account_index: 0,
            sender: [1; 20],
            recipient: [2; 20],
            value: Word::ZERO,
            nonce: Word::ZERO,
            gas_limit: Word::ZERO,
            quoted_base_fee: Word::ZERO,
            priority_fee: Word::ZERO,
            maximum_fee: Word::ZERO,
            estimated_network_fee: Word::ZERO,
            maximum_network_fee: Word::ZERO,
            estimated_spend: Word::ZERO,
            maximum_spend: Word::ZERO,
            quote_expires_at: Instant::now(),
        }));
        assert!(matches!(
            backend.add_custom_token_inner(&checksum_address(contract)),
            Err(BackendError::TokenMutationBlocked)
        ));
        backend.prepared = None;
        remove_test_backend_files(&backend);

        let mutable_rpc = MutableRpc::new();
        let legacy = legacy_unlocked_backend(mutable_rpc, TestClock::new(Instant::now()));
        assert!(matches!(
            legacy.refresh_custom_tokens_inner(),
            Err(BackendError::TokenRequiresV2)
        ));
        remove_test_backend_files(&legacy);
    }

    #[test]
    fn saved_erc20_prepare_preview_confirm_freezes_exact_fields() {
        let rpc = TokenRpc::new();
        let contract = [0x62; 20];
        let recipient = [0x63; 20];
        let mut backend = saved_token_backend(rpc.clone(), contract, 9);
        let active_epoch = std::sync::atomic::AtomicU64::new(0);
        let permit = SessionPermit::current_for_test(0, &active_epoch);
        let preview = backend
            .prepare_saved_erc20_transfer_inner(
                &checksum_address(contract),
                &checksum_address(recipient),
                "1.25",
                FeeSelection::Recommended,
                &permit,
            )
            .expect("prepare authenticated saved token transfer");
        assert!(preview.contract_address == checksum_address(contract));
        assert!(preview.recipient == checksum_address(recipient));
        assert!(preview.symbol.as_deref() == Some("TOK"));
        assert_eq!(preview.decimals, 2);
        assert_eq!(preview.amount, "1.25");
        assert_eq!(preview.estimated_gas, "50000");
        assert_eq!(preview.gas_limit, "60000");

        let prepared = match backend.prepared.as_ref().expect("token prepared") {
            PreparedTransfer::SavedErc20(prepared) => prepared,
            PreparedTransfer::Native(_) => panic!("expected saved token transfer"),
        };
        let expected_raw = {
            let UnlockedWallet::V2(opened) = backend.unlocked.as_ref().expect("v2 unlocked") else {
                panic!("token transfer requires v2")
            };
            let account_material = opened
                .wallet()
                .account_private_key(0)
                .expect("account zero signing material");
            sign_erc20_type_two(
                account_material.as_bytes(),
                prepared.sender,
                prepared.contract,
                prepared.recipient,
                prepared.amount,
                prepared.nonce,
                prepared.gas_limit,
                prepared.priority_fee,
                prepared.maximum_fee,
            )
            .expect("deterministic token signing")
            .bytes
            .to_vec()
        };
        {
            let state = rpc.state.lock().expect("token RPC observation lock");
            let observed = state
                .preflight_fields
                .last()
                .copied()
                .expect("exact preflight observation");
            assert!(observed.sender == prepared.sender);
            assert!(observed.contract == contract);
            assert!(observed.recipient == recipient);
            assert!(observed.amount == prepared.amount);
            assert!(observed.nonce == prepared.nonce);
            assert!(observed.gas_limit == Word::from_u64(60_000));
            assert!(observed.priority_fee == prepared.priority_fee);
            assert!(observed.maximum_fee == prepared.maximum_fee);
        }

        let receipt = backend
            .confirm_prepared_with_permit(&permit)
            .expect("confirm exact token transfer");
        let state = rpc.state.lock().expect("confirmed token RPC lock");
        assert_eq!(state.preflight_calls, 2);
        assert_eq!(state.estimate_calls, 2);
        assert_eq!(state.sent.len(), 1);
        assert!(state.sent[0] == expected_raw);
        assert!(receipt.transaction_hash == fixed_hex(&keccak32(&expected_raw)));
        drop(state);
        assert!(!backend.pending_broadcast_exists());
        remove_test_backend_files(&backend);
    }

    #[test]
    fn exact_token_preflight_false_or_malformed_never_reaches_signing() {
        for rejected_result in [abi_u8(0), vec![1_u8]] {
            let rpc = TokenRpc::new();
            let contract = [0x64; 20];
            let mut backend = saved_token_backend(rpc.clone(), contract, 10);
            rpc.update(|state| state.transfer_result = rejected_result);
            let active_epoch = std::sync::atomic::AtomicU64::new(0);
            let permit = SessionPermit::current_for_test(0, &active_epoch);
            assert!(matches!(
                backend.prepare_saved_erc20_transfer_inner(
                    &checksum_address(contract),
                    "0x6565656565656565656565656565656565656565",
                    "1",
                    FeeSelection::Recommended,
                    &permit,
                ),
                Err(BackendError::TokenTransferRejected)
            ));
            assert!(backend.prepared.is_none());
            assert_eq!(backend.sign_attempts, 0);
            let state = rpc.state.lock().expect("rejected token RPC lock");
            assert_eq!(state.estimate_calls, 1);
            assert_eq!(state.preflight_calls, 1);
            assert!(state.sent.is_empty());
            drop(state);
            remove_test_backend_files(&backend);
        }
    }

    #[test]
    fn saved_erc20_confirm_consumes_preview_on_authenticated_sidecar_or_identity_drift() {
        for drift in 0..3 {
            let rpc = TokenRpc::new();
            let contract = [0x68 + drift; 20];
            let recipient = [0x70; 20];
            let mut backend = saved_token_backend(rpc.clone(), contract, 20 + drift);
            let active_epoch = std::sync::atomic::AtomicU64::new(0);
            let permit = SessionPermit::current_for_test(0, &active_epoch);
            backend
                .prepare_saved_erc20_transfer_inner(
                    &checksum_address(contract),
                    &checksum_address(recipient),
                    "1",
                    FeeSelection::Recommended,
                    &permit,
                )
                .expect("prepare drift fixture");

            let expected = match drift {
                0 => {
                    let context = backend.token_context().expect("token context");
                    let mut replacement = backend
                        .load_token_store(&context)
                        .expect("load sidecar baseline")
                        .store;
                    replacement
                        .add(
                            TokenEntry::new([0x79; 20], 2, Some("TOK".to_owned()), [0x55; 32])
                                .expect("valid competing entry"),
                        )
                        .expect("advance authenticated sidecar generation");
                    let sealed = replacement
                        .seal(&context.key)
                        .expect("seal authenticated replacement");
                    write_atomic_token_store(&backend.token_store_path, sealed.as_slice())
                        .expect("install authenticated replacement");
                    BackendError::TokenStoreChanged
                }
                1 => {
                    rpc.update(|state| {
                        state
                            .contracts
                            .get_mut(&contract)
                            .expect("code drift fixture")
                            .code
                            .push(0x01);
                    });
                    BackendError::TokenCodeChanged
                }
                2 => {
                    rpc.update(|state| {
                        state
                            .contracts
                            .get_mut(&contract)
                            .expect("metadata drift fixture")
                            .decimals = abi_u8(3);
                    });
                    BackendError::TokenMetadataChanged
                }
                _ => unreachable!(),
            };

            let result = backend.confirm_prepared_with_permit(&permit);
            assert!(matches!(result, Err(error) if error == expected));
            assert!(
                backend.prepared.is_none(),
                "confirm must consume every preview"
            );
            assert_eq!(backend.sign_attempts, 0);
            assert!(!backend.pending_broadcast_exists());
            assert!(rpc.state.lock().expect("drift RPC lock").sent.is_empty());
            remove_test_backend_files(&backend);
        }
    }

    #[test]
    fn saved_erc20_confirm_rejects_balance_nonce_fee_estimate_and_inclusive_ttl_drift() {
        for drift in 0..6 {
            let rpc = TokenRpc::new();
            let contract = [0x72 + drift; 20];
            let recipient = [0x78; 20];
            let clock = TestClock::new(Instant::now());
            let mut backend =
                saved_token_backend_with_clock(rpc.clone(), contract, 30 + drift, clock.clone());
            let active_epoch = std::sync::atomic::AtomicU64::new(0);
            let permit = SessionPermit::current_for_test(0, &active_epoch);
            backend
                .prepare_saved_erc20_transfer_inner(
                    &checksum_address(contract),
                    &checksum_address(recipient),
                    "1",
                    FeeSelection::Recommended,
                    &permit,
                )
                .expect("prepare dynamic drift fixture");

            let expected = match drift {
                0 => {
                    rpc.update(|state| {
                        state
                            .contracts
                            .get_mut(&contract)
                            .expect("token balance fixture")
                            .balance = abi_u8(0);
                    });
                    BackendError::InsufficientTokenBalance
                }
                1 => {
                    rpc.update(|state| state.native_balance = Word::ZERO);
                    BackendError::InsufficientBalance
                }
                2 => {
                    rpc.update(|state| state.nonce = Word::from_u64(8));
                    BackendError::AccountChanged
                }
                3 => {
                    rpc.update(|state| state.token_estimated_gas = Word::from_u64(50_001));
                    BackendError::TokenGasEstimateInvalid
                }
                4 => {
                    rpc.update(|state| state.base_fee = Word::from_u64(1_500_000_000));
                    BackendError::QuoteChanged
                }
                5 => {
                    clock.advance(FEE_QUOTE_TTL);
                    BackendError::QuoteExpired
                }
                _ => unreachable!(),
            };

            let result = backend.confirm_prepared_with_permit(&permit);
            assert!(matches!(result, Err(error) if error == expected));
            assert!(
                backend.prepared.is_none(),
                "confirm must consume every preview"
            );
            assert_eq!(backend.sign_attempts, 0);
            assert!(!backend.pending_broadcast_exists());
            assert!(
                rpc.state
                    .lock()
                    .expect("dynamic drift RPC lock")
                    .sent
                    .is_empty()
            );
            remove_test_backend_files(&backend);
        }
    }

    #[test]
    fn saved_erc20_gas_estimate_bounds_and_u64_fit_are_exact() {
        for (estimate, expected_limit) in [
            (Word::from_u64(20_999), None),
            (Word::from_u64(21_000), Some("25200")),
            (Word::from_u64(416_666), Some("500000")),
            (Word::from_u64(416_667), None),
            (Word::from_be_bytes([0xff; 32]), None),
        ] {
            let rpc = TokenRpc::new();
            let contract = [0x7a; 20];
            let mut backend = saved_token_backend(rpc.clone(), contract, 40);
            rpc.update(|state| state.token_estimated_gas = estimate);
            let active_epoch = std::sync::atomic::AtomicU64::new(0);
            let permit = SessionPermit::current_for_test(0, &active_epoch);
            let result = backend.prepare_saved_erc20_transfer_inner(
                &checksum_address(contract),
                &checksum_address([0x7b; 20]),
                "1",
                FeeSelection::Recommended,
                &permit,
            );
            match expected_limit {
                Some(expected_limit) => {
                    let preview = result.expect("accepted bounded token gas estimate");
                    assert_eq!(preview.gas_limit, expected_limit);
                    backend.cancel_prepared_inner();
                }
                None => {
                    match result {
                        Err(BackendError::TokenGasEstimateInvalid) => {}
                        Err(error) => panic!("unexpected gas-boundary error: {error:?}"),
                        Ok(_) => panic!("out-of-policy gas estimate was accepted"),
                    }
                    assert!(backend.prepared.is_none());
                }
            }
            assert_eq!(backend.sign_attempts, 0);
            assert!(
                rpc.state
                    .lock()
                    .expect("gas boundary RPC lock")
                    .sent
                    .is_empty()
            );
            remove_test_backend_files(&backend);
        }
    }

    #[test]
    fn saved_erc20_confirm_permit_checkpoints_bound_sign_write_send_and_delete() {
        // Critical confirm checks: 19 is post-exact-preflight; 31 and 32 are
        // the checks bracketing the activity capacity/nonce reservation; 33
        // is post-sign/pre-write; 34 is post-write; 35 is the guarded RPC
        // post-reverify/pre-transport check; and 36 is
        // post-send/pre-activity-commit; and 37 is post-durable-activity,
        // pre-pending-delete. Every error consumes the prepared preview.
        for (
            revoke_on_check,
            expected_signs,
            expected_pending,
            expected_sends,
            expected_activity,
        ) in [
            (19, 0, false, 0, false),
            (31, 0, false, 0, false),
            (32, 0, false, 0, false),
            (33, 1, false, 0, false),
            (34, 1, true, 0, false),
            (35, 1, true, 0, false),
            (36, 1, true, 1, false),
            (37, 1, true, 1, true),
        ] {
            let rpc = TokenRpc::new();
            let contract = [0x7c; 20];
            let mut backend = saved_token_backend(rpc.clone(), contract, 50);
            let prepare_epoch = std::sync::atomic::AtomicU64::new(0);
            let prepare_permit = SessionPermit::current_for_test(0, &prepare_epoch);
            backend
                .prepare_saved_erc20_transfer_inner(
                    &checksum_address(contract),
                    &checksum_address([0x7d; 20]),
                    "1",
                    FeeSelection::Recommended,
                    &prepare_permit,
                )
                .expect("prepare permit-checkpoint token transfer");
            let confirm_epoch = std::sync::atomic::AtomicU64::new(0);
            let confirm_permit = SessionPermit::revoke_on_check(0, &confirm_epoch, revoke_on_check);

            assert!(matches!(
                backend.confirm_prepared_with_permit(&confirm_permit),
                Err(BackendError::Locked)
            ));
            assert!(backend.prepared.is_none());
            assert_eq!(
                backend.sign_attempts, expected_signs,
                "sign count at permit check {revoke_on_check}"
            );
            assert_eq!(
                backend.pending_broadcast_exists(),
                expected_pending,
                "pending state at permit check {revoke_on_check}"
            );
            assert_eq!(
                rpc.state.lock().expect("token permit RPC lock").sent.len(),
                expected_sends,
                "send count at permit check {revoke_on_check}"
            );
            assert_eq!(
                path_may_exist(&backend.activity_store_path),
                expected_activity,
                "activity commit at permit check {revoke_on_check}"
            );
            remove_test_backend_files(&backend);
        }
    }

    #[test]
    fn ambiguous_erc20_broadcast_retries_exact_pending_bytes_without_resigning() {
        let rpc = TokenRpc::new();
        let contract = [0x66; 20];
        let mut backend = saved_token_backend(rpc.clone(), contract, 11);
        let active_epoch = std::sync::atomic::AtomicU64::new(0);
        let permit = SessionPermit::current_for_test(0, &active_epoch);
        backend
            .prepare_saved_erc20_transfer_inner(
                &checksum_address(contract),
                "0x6767676767676767676767676767676767676767",
                "1",
                FeeSelection::Recommended,
                &permit,
            )
            .expect("prepare ambiguous token transfer");
        rpc.update(|state| state.send_fails = true);
        assert!(matches!(
            backend.confirm_prepared_with_permit(&permit),
            Err(BackendError::BroadcastUnknown)
        ));
        assert!(backend.pending_broadcast_exists());
        assert_eq!(backend.sign_attempts, 1);
        let (first_raw, query_counts) = {
            let state = rpc.state.lock().expect("ambiguous token RPC lock");
            (
                state.sent[0].clone(),
                (
                    state.query_calls,
                    state.preflight_calls,
                    state.estimate_calls,
                    state.nonce_calls,
                    state.quote_calls,
                    state.base_fee_calls,
                    state.native_balance_calls,
                ),
            )
        };
        rpc.update(|state| state.send_fails = false);
        let receipt = backend
            .retry_pending_inner()
            .expect("retry exact token pending bytes");
        assert_eq!(backend.sign_attempts, 1);
        let state = rpc.state.lock().expect("retried token RPC lock");
        assert_eq!(state.sent.len(), 2);
        assert!(state.sent[0] == first_raw && state.sent[1] == first_raw);
        assert!(
            query_counts
                == (
                    state.query_calls,
                    state.preflight_calls,
                    state.estimate_calls,
                    state.nonce_calls,
                    state.quote_calls,
                    state.base_fee_calls,
                    state.native_balance_calls,
                )
        );
        assert!(receipt.transaction_hash == fixed_hex(&keccak32(&first_raw)));
        drop(state);
        assert!(!backend.pending_broadcast_exists());
        remove_test_backend_files(&backend);
    }

    #[test]
    fn account_one_erc20_restart_observes_exact_pending_without_rebroadcast() {
        let rpc = TokenRpc::new();
        let contract = [0x6a; 20];
        rpc.insert(contract, token_fixture(23));
        let vault = temporary_vault();
        let mut backend = DemoBackend::with_rpc(vault.clone(), rpc.clone());
        let initial = import_generated_mnemonic(&mut backend);
        let account_one = initial.accounts[1].address.clone();
        backend.select_account_inner(1).expect("select account one");
        backend
            .add_custom_token_inner(&checksum_address(contract))
            .expect("save token for account one");
        let epoch = std::sync::atomic::AtomicU64::new(0);
        let permit = SessionPermit::current_for_test(0, &epoch);
        let recipient = [0x6b; 20];
        backend
            .prepare_saved_erc20_transfer_inner(
                &checksum_address(contract),
                &checksum_address(recipient),
                "1.25",
                FeeSelection::Recommended,
                &permit,
            )
            .expect("prepare account-one ERC20 transfer");
        rpc.update(|state| state.send_fails = true);
        assert!(matches!(
            backend.confirm_prepared_with_permit(&permit),
            Err(BackendError::BroadcastUnknown)
        ));
        let exact_raw = rpc.state.lock().expect("account-one ERC20 send state").sent[0].clone();
        backend.lock();
        drop(backend);

        let mut restarted = DemoBackend::with_rpc(vault, rpc.clone());
        let opened = restarted
            .open(TEST_PASSWORD)
            .expect("reopen account-one ERC20 pending");
        let pending = opened
            .pending_broadcast
            .as_ref()
            .expect("attribute account-one ERC20 pending");
        assert_eq!(pending.sender_account_index, 1);
        assert_eq!(pending.sender_address, account_one);
        let prepared = restarted
            .prepared_pending_retry
            .as_ref()
            .expect("frozen account-one ERC20 pending after open");
        assert_eq!(prepared.raw_transaction.as_slice(), exact_raw.as_slice());
        let identity = restarted
            .pending_activity_identity(prepared)
            .expect("bind account-one saved-token metadata");
        assert_eq!(identity.account_index(), 1);
        assert_eq!(identity.sender(), &prepared.sender);
        assert_eq!(identity.transfer().contract(), Some(&contract));
        assert_eq!(identity.transfer().recipient(), &recipient);
        let observed = observed_transaction_from_exact_pending(&identity, &exact_raw);
        assert_eq!(
            observed.input,
            erc20::transfer_call_data(
                recipient,
                TokenAmount::from_be_bytes(
                    *identity
                        .transfer()
                        .raw_amount()
                        .expect("account-one ERC20 raw amount"),
                ),
            )
        );
        rpc.update(|state| {
            state.send_fails = false;
            state.observed_transaction = Some(observed);
        });

        let retry_epoch = std::sync::atomic::AtomicU64::new(0);
        let retry_permit = SessionPermit::current_for_test(0, &retry_epoch);
        let receipt = restarted
            .retry_pending_with_permit(&retry_permit)
            .expect("observe exact account-one ERC20 without rebroadcast");
        assert!(!receipt.broadcast_performed);
        assert_eq!(restarted.sign_attempts, 0);
        assert!(!restarted.pending_broadcast_exists());
        let state = rpc.state.lock().expect("account-one ERC20 observed state");
        assert_eq!(state.sent.len(), 1);
        assert_eq!(state.sent[0], exact_raw);
        assert!(state.activity_transaction_calls >= 1);
        drop(state);
        let activity = receipt
            .activity
            .expect("durable account-one ERC20 activity");
        assert_eq!(activity.sender_account_index, 1);
        assert_eq!(activity.sender_address, account_one);
        remove_test_backend_files(&restarted);
    }

    #[test]
    fn token_errors_are_category_only_and_cross_the_ui_allowlist() {
        let errors = [
            BackendError::TokenRequiresV2,
            BackendError::TokenContractAddressInvalid,
            BackendError::TokenContractEmpty,
            BackendError::TokenQueryUnavailable,
            BackendError::TokenMetadataInvalid,
            BackendError::TokenCodeChanged,
            BackendError::TokenMetadataChanged,
            BackendError::TokenTransferRejected,
            BackendError::TokenGasEstimateInvalid,
            BackendError::InsufficientTokenBalance,
            BackendError::TokenDuplicate,
            BackendError::TokenCapacity,
            BackendError::TokenNotFound,
            BackendError::TokenStoreInvalid,
            BackendError::TokenStoreStorage,
            BackendError::TokenStoreChanged,
            BackendError::TokenMutationBlocked,
        ];
        for error in errors {
            let mapped = error_text(error);
            assert_eq!(crate::ui::safe_error(mapped.clone()), mapped, "{error:?}");
            for forbidden in [
                "0x1111111111111111111111111111111111111111",
                "TOK",
                "12.35",
                "https://",
                "eth_call",
            ] {
                assert!(!mapped.contains(forbidden), "{error:?}");
            }
        }
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
            BackendError::BackupConfirmationFailed,
            BackendError::MigrationCleanup,
            BackendError::MnemonicUnavailable,
            BackendError::RandomnessUnavailable,
            BackendError::CryptographicFailure,
            BackendError::Locked,
            BackendError::RpcUnavailable,
            BackendError::BalanceUnavailable,
            BackendError::TokenRequiresV2,
            BackendError::TokenContractAddressInvalid,
            BackendError::TokenContractEmpty,
            BackendError::TokenQueryUnavailable,
            BackendError::TokenMetadataInvalid,
            BackendError::TokenCodeChanged,
            BackendError::TokenMetadataChanged,
            BackendError::TokenTransferRejected,
            BackendError::TokenGasEstimateInvalid,
            BackendError::InsufficientTokenBalance,
            BackendError::TokenDuplicate,
            BackendError::TokenCapacity,
            BackendError::TokenNotFound,
            BackendError::TokenStoreInvalid,
            BackendError::TokenStoreStorage,
            BackendError::TokenStoreChanged,
            BackendError::TokenMutationBlocked,
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
        let prepared = native_prepared(&backend);
        let expected = sign_native_type_two(
            &[7_u8; KEY_BYTES],
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
    fn confirm_revocation_checkpoints_bound_signing_pending_and_broadcast() {
        // Checks are: entry; after pending-file metadata; after verify, nonce, base-fee, balance and
        // estimate RPCs; activity capacity/nonce reservation; pre-sign;
        // pre-pending-write; post-pending-write; guarded RPC
        // post-reverify/pre-transport; post-send/pre-activity-commit; and the
        // post-durable-activity/pre-pending-delete boundary.
        for (
            revoke_on_check,
            expected_signs,
            expected_pending,
            expected_sends,
            expected_activity,
        ) in [
            (3, 0, false, 0, false),
            (8, 0, false, 0, false),
            (9, 0, false, 0, false),
            (10, 1, false, 0, false),
            (11, 1, true, 0, false),
            (12, 1, true, 0, false),
            (13, 1, true, 1, false),
            (14, 1, true, 1, true),
        ] {
            let (mut backend, rpc, _) = prepared_mutable_backend();
            let active_epoch = std::sync::atomic::AtomicU64::new(0);
            let permit = SessionPermit::revoke_on_check(0, &active_epoch, revoke_on_check);

            assert!(matches!(
                backend.confirm_prepared_with_permit(&permit),
                Err(BackendError::Locked)
            ));
            assert_eq!(backend.sign_attempts, expected_signs);
            assert_eq!(backend.pending_broadcast_exists(), expected_pending);
            let state = rpc.state.lock().expect("revoked confirm RPC lock");
            assert_eq!(state.sent.len(), expected_sends);
            if revoke_on_check == 3 {
                assert_eq!(state.verify_calls, 2);
                assert_eq!(state.nonce_calls, 1);
                assert_eq!(state.base_fee_calls, 0);
                assert_eq!(state.balance_calls, 1);
                assert_eq!(state.estimate_calls, 1);
            }
            drop(state);
            assert_eq!(
                path_may_exist(&backend.activity_store_path),
                expected_activity,
                "activity commit at permit check {revoke_on_check}"
            );
            remove_test_backend_files(&backend);
        }
    }

    #[test]
    fn retry_revocation_before_and_after_send_preserves_pending_record() {
        let (mut backend, rpc, _) = prepared_mutable_backend();
        rpc.update(|state| state.send_fails = true);
        assert!(matches!(
            backend.confirm_prepared_inner(),
            Err(BackendError::BroadcastUnknown)
        ));
        assert!(backend.pending_broadcast_exists());
        rpc.update(|state| {
            state.send_fails = false;
            state.sent.clear();
        });

        // The named pre-send checkpoints remain intentionally distinct: the
        // first exact-record verification exits at check 3, while the RPC
        // transport itself performs check 6 after the second exact-record
        // verification. Revocation at either boundary emits no new broadcast
        // and retains the exact signed record.
        const FIRST_EXACT_VERIFY_EXIT: usize = 3;
        const RPC_TRANSPORT_ENTRY: usize = 6;
        backend
            .prepare_pending_retry(None)
            .expect("attribute pending before revoked retry");
        let pre_send_epoch = std::sync::atomic::AtomicU64::new(0);
        let pre_send_permit =
            SessionPermit::revoke_on_check(0, &pre_send_epoch, FIRST_EXACT_VERIFY_EXIT);
        assert!(matches!(
            backend.retry_pending_with_permit(&pre_send_permit),
            Err(BackendError::Locked)
        ));
        assert!(backend.pending_broadcast_exists());
        assert!(
            rpc.state
                .lock()
                .expect("pre-send retry RPC lock")
                .sent
                .is_empty()
        );

        backend
            .prepare_pending_retry(None)
            .expect("reattribute pending before guarded retry");
        let guarded_send_epoch = std::sync::atomic::AtomicU64::new(0);
        let guarded_send_permit =
            SessionPermit::revoke_on_check(0, &guarded_send_epoch, RPC_TRANSPORT_ENTRY);
        assert!(matches!(
            backend.retry_pending_with_permit(&guarded_send_permit),
            Err(BackendError::Locked)
        ));
        assert!(backend.pending_broadcast_exists());
        assert!(
            rpc.state
                .lock()
                .expect("guarded-send retry RPC lock")
                .sent
                .is_empty()
        );

        // A named transport hook now revokes immediately after recording the
        // external send and before returning the matching response. This is
        // independent of how many exact-file checks precede transport: the
        // local recovery record must not be deleted after that committed send.
        backend
            .prepare_pending_retry(None)
            .expect("reattribute pending before post-send retry");
        let post_send_epoch = Arc::new(std::sync::atomic::AtomicU64::new(0));
        rpc.update(|state| state.revoke_epoch_after_send = Some(post_send_epoch.clone()));
        let post_send_permit = SessionPermit::current_for_test(0, post_send_epoch.as_ref());
        assert!(matches!(
            backend.retry_pending_with_permit(&post_send_permit),
            Err(BackendError::Locked)
        ));
        assert!(backend.pending_broadcast_exists());
        assert_eq!(
            rpc.state
                .lock()
                .expect("post-send retry RPC lock")
                .sent
                .len(),
            1
        );
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
        backend
            .import_private_key(
                sensitive(&fixed_hex(&[7_u8; KEY_BYTES])),
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            )
            .expect("create v2 wallet");
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
    fn erc20_signer_golden_decodes_exact_type_two_fields() {
        fn header(input: &[u8]) -> (bool, usize, usize, usize) {
            let first = input[0];
            match first {
                0x00..=0x7f => (false, 0, 1, 1),
                0x80..=0xb7 => {
                    let length = usize::from(first - 0x80);
                    (false, 1, length, 1 + length)
                }
                0xb8..=0xbf => {
                    let length_bytes = usize::from(first - 0xb7);
                    let length = input[1..=length_bytes]
                        .iter()
                        .fold(0_usize, |value, byte| (value << 8) | usize::from(*byte));
                    (false, 1 + length_bytes, length, 1 + length_bytes + length)
                }
                0xc0..=0xf7 => {
                    let length = usize::from(first - 0xc0);
                    (true, 1, length, 1 + length)
                }
                0xf8..=0xff => {
                    let length_bytes = usize::from(first - 0xf7);
                    let length = input[1..=length_bytes]
                        .iter()
                        .fold(0_usize, |value, byte| (value << 8) | usize::from(*byte));
                    (true, 1 + length_bytes, length, 1 + length_bytes + length)
                }
            }
        }

        fn golden_length(short: u8, long: u8, length: usize) -> Vec<u8> {
            if length <= 55 {
                return vec![short + u8::try_from(length).expect("short golden RLP length")];
            }
            let encoded = length.to_be_bytes();
            let first = encoded
                .iter()
                .position(|byte| *byte != 0)
                .expect("nonzero golden RLP length");
            let significant = &encoded[first..];
            let mut output =
                vec![long + u8::try_from(significant.len()).expect("golden RLP length-of-length")];
            output.extend_from_slice(significant);
            output
        }

        fn golden_bytes(bytes: &[u8]) -> Vec<u8> {
            if bytes.len() == 1 && bytes[0] < 0x80 {
                return bytes.to_vec();
            }
            let mut output = golden_length(0x80, 0xb7, bytes.len());
            output.extend_from_slice(bytes);
            output
        }

        fn golden_list(items: &[Vec<u8>]) -> Vec<u8> {
            let length = items.iter().map(Vec::len).sum();
            let mut output = golden_length(0xc0, 0xf7, length);
            for item in items {
                output.extend_from_slice(item);
            }
            output
        }

        let signing_material = [0x12; 32];
        let sender = address_from_private_key(&signing_material).expect("derive golden sender");
        let contract = [0x34; 20];
        let recipient = [0x56; 20];
        let mut amount_bytes = [0_u8; 32];
        amount_bytes[30..].copy_from_slice(&0x1234_u16.to_be_bytes());
        let amount = TokenAmount::from_be_bytes(amount_bytes);
        let signed = sign_erc20_type_two(
            &signing_material,
            sender,
            contract,
            recipient,
            amount,
            Word::from_u64(7),
            Word::from_u64(60_000),
            Word::from_u64(1_000_000_000),
            Word::from_u64(2_000_000_000),
        )
        .expect("sign exact ERC20 golden transaction");
        assert_eq!(signed.bytes.first(), Some(&2));
        let encoded_list = &signed.bytes[1..];
        let (is_list, payload_start, payload_length, total) = header(encoded_list);
        assert!(is_list && total == encoded_list.len());
        let payload = &encoded_list[payload_start..payload_start + payload_length];
        let mut fields = Vec::new();
        let mut offset = 0;
        while offset < payload.len() {
            let (field_is_list, start, length, consumed) = header(&payload[offset..]);
            fields.push((
                field_is_list,
                payload[offset + start..offset + start + length].to_vec(),
            ));
            offset += consumed;
        }
        assert_eq!(fields.len(), 12);
        assert!(fields[0].1 == vec![0xaa, 0x36, 0xa7]);
        assert!(fields[1].1 == vec![7]);
        assert!(fields[2].1 == vec![0x3b, 0x9a, 0xca, 0x00]);
        assert!(fields[3].1 == vec![0x77, 0x35, 0x94, 0x00]);
        assert!(fields[4].1 == vec![0xea, 0x60]);
        assert!(fields[5].1 == contract);
        assert!(!fields[6].0 && fields[6].1.is_empty());
        let mut expected_calldata = [0_u8; 68];
        expected_calldata[..4].copy_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        expected_calldata[16..36].copy_from_slice(&recipient);
        expected_calldata[36..].copy_from_slice(&amount_bytes);
        assert!(fields[7].1 == expected_calldata);
        assert!(fields[7].1.len() == 68);
        assert!(fields[8].0 && fields[8].1.is_empty());
        assert!(!fields[9].0 && fields[9].1.len() <= 1);
        assert!(!fields[10].0 && !fields[10].1.is_empty() && fields[10].1.len() <= 32);
        assert!(!fields[11].0 && !fields[11].1.is_empty() && fields[11].1.len() <= 32);

        // Rebuild the unsigned type-2 preimage and recover the sender only
        // from independently decoded fields and a separate local RLP encoder.
        let unsigned_fields = fields[..9]
            .iter()
            .map(|(is_list, bytes)| {
                if *is_list {
                    assert!(bytes.is_empty(), "only the empty access list is accepted");
                    golden_list(&[])
                } else {
                    golden_bytes(bytes)
                }
            })
            .collect::<Vec<_>>();
        let mut unsigned = vec![2_u8];
        unsigned.extend_from_slice(&golden_list(&unsigned_fields));
        let decoded_prehash: [u8; 32] = Keccak256::digest(&unsigned).into();
        let y_parity = fields[9].1.first().copied().unwrap_or(0);
        assert!(y_parity <= 1);
        let mut decoded_signature = [0_u8; 64];
        decoded_signature[32 - fields[10].1.len()..32].copy_from_slice(&fields[10].1);
        decoded_signature[64 - fields[11].1.len()..].copy_from_slice(&fields[11].1);
        let recoverable = RecoverableSignature::from_compact(
            &decoded_signature,
            RecoveryId::try_from(i32::from(y_parity)).expect("decoded recovery id"),
        )
        .expect("decoded compact signature");
        let recovered = Secp256k1::new()
            .recover_ecdsa(Message::from_digest(decoded_prehash), &recoverable)
            .expect("recover decoded golden sender");
        let serialized = recovered.serialize_uncompressed();
        let recovered_hash = Keccak256::digest(&serialized[1..]);
        assert_eq!(&recovered_hash[12..], sender);
        assert!(signed.transaction_hash == keccak32(signed.bytes.as_slice()));
    }

    #[test]
    fn zero_y_parity_uses_canonical_rlp_empty_integer() {
        assert_eq!(rlp_integer(&[0]), vec![0x80]);
        assert_eq!(rlp_integer(&[1]), vec![0x01]);
    }

    #[test]
    fn pending_type_two_recovery_accepts_bounded_signers_and_rejects_every_canonicality_axis() {
        let recipient = [0x45; 20];
        let mut valid_transactions = Vec::new();
        for key_marker in [0x12, 0x13] {
            let key = [key_marker; 32];
            let sender = address_from_private_key(&key).expect("derive native pending signer");
            let signed = sign_native_type_two(
                &key,
                sender,
                recipient,
                Word::from_u64(1_000_000_000_000_000),
                Word::from_u64(7),
                Word::from_u64(NATIVE_TRANSFER_GAS),
                Word::from_u64(1_000_000_000),
                Word::from_u64(2_000_000_000),
            )
            .expect("sign valid bounded native pending fixture");
            assert_eq!(
                recover_signed_type_two_sender(signed.bytes.as_slice())
                    .expect("recover valid native pending sender"),
                sender
            );
            valid_transactions.push(signed.bytes.to_vec());

            let amount = TokenAmount::from_be_bytes({
                let mut bytes = [0_u8; 32];
                bytes[31] = 1;
                bytes
            });
            let token = sign_erc20_type_two(
                &key,
                sender,
                [0x46; 20],
                recipient,
                amount,
                Word::from_u64(8),
                Word::from_u64(60_000),
                Word::from_u64(1_000_000_000),
                Word::from_u64(2_000_000_000),
            )
            .expect("sign valid bounded ERC20 pending fixture");
            assert_eq!(
                recover_signed_type_two_sender(token.bytes.as_slice())
                    .expect("recover valid ERC20 pending sender"),
                sender
            );
        }

        let valid = valid_transactions.remove(0);
        let fields = signed_type_two_fields(&valid);
        assert_eq!(fields.len(), 12);
        let mut invalid = Vec::new();
        invalid.push(("truncated", valid[..valid.len() - 1].to_vec()));
        let mut trailing = valid.clone();
        trailing.push(0);
        invalid.push(("trailing", trailing));
        let mut thirteen = fields.clone();
        thirteen.push(rlp_integer(&[]));
        invalid.push(("thirteenth field", rebuild_signed_type_two(&thirteen)));

        let mut noncanonical_single = fields.clone();
        noncanonical_single[1] = vec![0x81, 0x07];
        invalid.push((
            "noncanonical single byte",
            rebuild_signed_type_two(&noncanonical_single),
        ));
        let mut noncanonical_long = fields.clone();
        noncanonical_long[5] = {
            let mut encoded = vec![0xb8, 20];
            encoded.extend_from_slice(&recipient);
            encoded
        };
        invalid.push((
            "noncanonical long length",
            rebuild_signed_type_two(&noncanonical_long),
        ));
        let mut leading_zero = fields.clone();
        leading_zero[2] = rlp_bytes(&[0, 1]);
        invalid.push((
            "leading-zero integer",
            rebuild_signed_type_two(&leading_zero),
        ));
        let mut wrong_chain = fields.clone();
        wrong_chain[0] = rlp_word(Word::from_u64(1));
        invalid.push(("wrong chain", rebuild_signed_type_two(&wrong_chain)));
        let mut nonempty_access = fields.clone();
        nonempty_access[8] = rlp_list(&[rlp_list(&[])]);
        invalid.push((
            "nonempty access list",
            rebuild_signed_type_two(&nonempty_access),
        ));
        let mut unsupported_data = fields.clone();
        unsupported_data[7] = rlp_bytes(&[1]);
        invalid.push((
            "unsupported calldata",
            rebuild_signed_type_two(&unsupported_data),
        ));
        let mut wrong_gas = fields.clone();
        wrong_gas[4] = rlp_word(Word::from_u64(NATIVE_TRANSFER_GAS + 1));
        invalid.push(("unsupported gas", rebuild_signed_type_two(&wrong_gas)));
        let mut zero_value = fields.clone();
        zero_value[6] = rlp_word(Word::ZERO);
        invalid.push(("unsupported value", rebuild_signed_type_two(&zero_value)));
        let mut bad_y = fields.clone();
        bad_y[9] = rlp_integer(&[2]);
        invalid.push(("y parity two", rebuild_signed_type_two(&bad_y)));
        let mut zero_r = fields.clone();
        zero_r[10] = rlp_integer(&[]);
        invalid.push(("zero r", rebuild_signed_type_two(&zero_r)));
        let mut zero_s = fields.clone();
        zero_s[11] = rlp_integer(&[]);
        invalid.push(("zero s", rebuild_signed_type_two(&zero_s)));
        let mut out_of_range_r = fields.clone();
        out_of_range_r[10] = rlp_integer(&[0xff; 32]);
        invalid.push(("out-of-range r", rebuild_signed_type_two(&out_of_range_r)));
        let mut high_s = fields;
        high_s[11] = rlp_integer(&[
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46,
            0x68, 0x1b, 0x20, 0xa1,
        ]);
        invalid.push(("high s", rebuild_signed_type_two(&high_s)));

        for (case, raw) in invalid {
            assert!(
                matches!(
                    recover_signed_type_two_sender(&raw),
                    Err(BackendError::PendingInvalid)
                ),
                "invalid pending axis must fail closed: {case}"
            );
        }
    }

    #[test]
    fn pending_open_rejects_foreign_or_tampered_raw_and_exact_lease_blocks_replacement() {
        let local_key = [0x21; 32];
        let foreign_key = [0x22; 32];
        let foreign_sender =
            address_from_private_key(&foreign_key).expect("derive foreign pending signer");
        let foreign = sign_native_type_two(
            &foreign_key,
            foreign_sender,
            [0x45; 20],
            Word::from_u64(1_000_000_000_000_000),
            Word::from_u64(7),
            Word::from_u64(NATIVE_TRANSFER_GAS),
            Word::from_u64(1_000_000_000),
            Word::from_u64(2_000_000_000),
        )
        .expect("sign foreign pending fixture");
        let mut foreign_backend = DemoBackend::with_rpc(temporary_vault(), test_rpc());
        foreign_backend
            .import_private_key(
                sensitive(&fixed_hex(&local_key)),
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            )
            .expect("import local pending wallet");
        write_new_pending(
            &foreign_backend.pending_path,
            foreign.transaction_hash,
            foreign.bytes.as_slice(),
        )
        .expect("persist foreign signed pending fixture");
        foreign_backend.lock();
        assert!(matches!(
            foreign_backend.open(TEST_PASSWORD),
            Err(BackendError::PendingAccountMismatch)
        ));
        assert!(foreign_backend.unlocked.is_none());
        assert!(foreign_backend.pending_broadcast_exists());
        remove_test_backend_files(&foreign_backend);

        let local_sender = address_from_private_key(&local_key).expect("derive local signer");
        let signed = sign_native_type_two(
            &local_key,
            local_sender,
            [0x45; 20],
            Word::from_u64(1_000_000_000_000_000),
            Word::from_u64(7),
            Word::from_u64(NATIVE_TRANSFER_GAS),
            Word::from_u64(1_000_000_000),
            Word::from_u64(2_000_000_000),
        )
        .expect("sign local pending fixture");
        let mut tampered_backend = DemoBackend::with_rpc(temporary_vault(), test_rpc());
        tampered_backend
            .import_private_key(
                sensitive(&fixed_hex(&local_key)),
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            )
            .expect("import tampered pending wallet");
        let mut tampered = signed.bytes.to_vec();
        tampered.push(0);
        write_new_pending(
            &tampered_backend.pending_path,
            keccak32(&tampered),
            &tampered,
        )
        .expect("persist hash-consistent tampered pending fixture");
        tampered_backend.lock();
        assert!(matches!(
            tampered_backend.open(TEST_PASSWORD),
            Err(BackendError::PendingInvalid)
        ));
        assert!(tampered_backend.unlocked.is_none());
        remove_test_backend_files(&tampered_backend);

        let mut leased = DemoBackend::with_rpc(temporary_vault(), test_rpc());
        leased
            .import_private_key(
                sensitive(&fixed_hex(&local_key)),
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            )
            .expect("import exact-lease pending wallet");
        write_new_pending(
            &leased.pending_path,
            signed.transaction_hash,
            signed.bytes.as_slice(),
        )
        .expect("persist exact-lease pending fixture");
        leased.lock();
        let opened = leased
            .open(TEST_PASSWORD)
            .expect("open and pin exact pending object");
        assert_eq!(
            opened
                .pending_broadcast
                .as_ref()
                .map(|preview| preview.sender_account_index),
            Some(0)
        );
        #[cfg(windows)]
        {
            assert!(fs::remove_file(&leased.pending_path).is_err());
            assert!(
                OpenOptions::new()
                    .write(true)
                    .open(&leased.pending_path)
                    .is_err()
            );
            let replacement = leased
                .pending_path
                .with_file_name("pending-replacement.bin");
            fs::write(&replacement, b"replacement").expect("write replacement probe");
            assert!(fs::rename(&replacement, &leased.pending_path).is_err());
            let _ = fs::remove_file(replacement);
        }
        let epoch = std::sync::atomic::AtomicU64::new(0);
        let permit = SessionPermit::current_for_test(0, &epoch);
        leased
            .retry_pending_with_permit(&permit)
            .expect("delete only held exact object after matching retry");
        assert!(!leased.pending_broadcast_exists());
        remove_test_backend_files(&leased);
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
        backend
            .import_private_key(
                sensitive(&fixed_hex(&[7_u8; KEY_BYTES])),
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            )
            .expect("create v2 wallet");
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
    fn accepted_broadcast_then_activity_commit_failure_retries_by_observation_without_resend() {
        let (mut backend, rpc, _) = prepared_mutable_backend();
        backend.fail_activity_persist_for_test = true;
        assert!(matches!(
            backend.confirm_prepared_inner(),
            Err(BackendError::ActivityStoreStorage)
        ));
        assert!(backend.pending_broadcast_exists());
        assert_eq!(
            rpc.state.lock().expect("RPC state after send").sent.len(),
            1
        );
        assert!(!path_may_exist(&backend.activity_store_path));

        backend.fail_activity_persist_for_test = false;
        backend
            .prepare_pending_retry(None)
            .expect("freeze pending left by activity commit failure");
        let identity = backend
            .pending_activity_identity(
                backend
                    .prepared_pending_retry
                    .as_ref()
                    .expect("prepared pending retry"),
            )
            .expect("reconstruct exact pending activity identity");
        rpc.update(|state| {
            state.observed_transaction = Some(observed_transaction_for_identity(&identity));
        });

        let receipt = backend
            .retry_pending_inner()
            .expect("observe accepted transaction and commit without resend");
        assert!(!receipt.broadcast_performed);
        assert_eq!(
            receipt.transaction_hash,
            fixed_hex(identity.transaction_hash())
        );
        assert!(receipt.activity.is_some());
        assert!(!backend.pending_broadcast_exists());
        assert_eq!(
            rpc.state
                .lock()
                .expect("RPC state after recovery")
                .sent
                .len(),
            1
        );

        let context = backend.activity_context().expect("v2 activity context");
        let loaded = backend
            .load_activity_store(&context)
            .expect("authenticated activity readback");
        assert!(
            loaded
                .store
                .find(identity.transaction_hash())
                .is_some_and(|entry| entry.identity() == &identity)
        );
        remove_test_backend_files(&backend);
    }

    #[test]
    fn committed_activity_with_leftover_pending_cleans_exact_file_without_network() {
        let (mut backend, rpc, _) = prepared_mutable_backend();
        rpc.update(|state| state.send_fails = true);
        assert!(matches!(
            backend.confirm_prepared_inner(),
            Err(BackendError::BroadcastUnknown)
        ));
        assert!(backend.pending_broadcast_exists());
        backend
            .prepare_pending_retry(None)
            .expect("freeze pending for committed-row recovery fixture");
        let identity = backend
            .pending_activity_identity(
                backend
                    .prepared_pending_retry
                    .as_ref()
                    .expect("prepared committed-row fixture"),
            )
            .expect("reconstruct committed-row identity");
        backend.prepared_pending_retry = None;

        let context = backend.activity_context().expect("v2 activity context");
        let activity_lease = ActivityMutationLease::acquire(&backend.activity_store_path)
            .expect("activity mutation lease");
        let mut loaded = backend
            .load_activity_store(&context)
            .expect("empty activity store");
        backend
            .commit_submitted_activity(&activity_lease, &context, &mut loaded, &identity)
            .expect("durably commit activity before pending cleanup");
        drop(activity_lease);
        let sent_before = rpc
            .state
            .lock()
            .expect("RPC state before cleanup")
            .sent
            .len();
        rpc.update(|state| state.send_fails = false);

        let receipt = backend
            .retry_pending_inner()
            .expect("clean leftover exact pending from committed activity");
        assert!(!receipt.broadcast_performed);
        assert_eq!(
            receipt.transaction_hash,
            fixed_hex(identity.transaction_hash())
        );
        assert!(!backend.pending_broadcast_exists());
        assert_eq!(
            rpc.state
                .lock()
                .expect("RPC state after cleanup")
                .sent
                .len(),
            sent_before
        );
        remove_test_backend_files(&backend);
    }

    #[test]
    fn retry_nonce_collision_preserves_exact_pending_before_node_lookup_or_resend() {
        let (mut backend, rpc, _) = prepared_mutable_backend();
        rpc.update(|state| state.send_fails = true);
        assert!(matches!(
            backend.confirm_prepared_inner(),
            Err(BackendError::BroadcastUnknown)
        ));
        backend
            .prepare_pending_retry(None)
            .expect("freeze pending collision fixture");
        let pending_identity = backend
            .pending_activity_identity(
                backend
                    .prepared_pending_retry
                    .as_ref()
                    .expect("prepared pending collision fixture"),
            )
            .expect("pending collision identity");
        backend.prepared_pending_retry = None;
        let conflicting = TransactionIdentity::native(
            [0x78; 32],
            *pending_identity.sender(),
            pending_identity.account_index(),
            *pending_identity.nonce(),
            *pending_identity.gas_limit(),
            *pending_identity.max_priority_fee_per_gas(),
            *pending_identity.max_fee_per_gas(),
            *pending_identity.transfer().recipient(),
            *pending_identity
                .transfer()
                .native_value()
                .expect("native pending collision value"),
        )
        .expect("different hash in same pending nonce slot");
        let context = backend.activity_context().expect("v2 activity context");
        let activity_lease = ActivityMutationLease::acquire(&backend.activity_store_path)
            .expect("activity mutation lease");
        let mut loaded = backend
            .load_activity_store(&context)
            .expect("empty activity store");
        backend
            .commit_submitted_activity(&activity_lease, &context, &mut loaded, &conflicting)
            .expect("commit conflicting nonce-slot fixture");
        drop(activity_lease);
        let (sent_before, lookup_before) = {
            let state = rpc.state.lock().expect("RPC state before collision retry");
            (state.sent.len(), state.activity_transaction_calls)
        };
        rpc.update(|state| state.send_fails = false);

        assert!(matches!(
            backend.retry_pending_inner(),
            Err(BackendError::ActivityNonceConflict)
        ));
        assert!(backend.pending_broadcast_exists());
        let state = rpc.state.lock().expect("RPC state after collision retry");
        assert_eq!(state.sent.len(), sent_before);
        assert_eq!(state.activity_transaction_calls, lookup_before);
        drop(state);
        remove_test_backend_files(&backend);
    }

    #[test]
    fn occupied_activity_nonce_slot_rejects_before_sign_pending_or_send() {
        let (mut backend, rpc, _) = prepared_mutable_backend();
        let prepared = native_prepared(&backend);
        let occupied = TransactionIdentity::native(
            [0x55; 32],
            prepared.sender,
            prepared.account_index,
            *prepared.nonce.as_be_bytes(),
            *prepared.gas_limit.as_be_bytes(),
            *prepared.priority_fee.as_be_bytes(),
            *prepared.maximum_fee.as_be_bytes(),
            prepared.recipient,
            *prepared.value.as_be_bytes(),
        )
        .expect("occupied nonce-slot activity identity");
        let context = backend.activity_context().expect("v2 activity context");
        let activity_lease = ActivityMutationLease::acquire(&backend.activity_store_path)
            .expect("activity mutation lease");
        let mut loaded = backend
            .load_activity_store(&context)
            .expect("empty activity store");
        backend
            .commit_submitted_activity(&activity_lease, &context, &mut loaded, &occupied)
            .expect("commit occupied nonce-slot fixture");
        drop(activity_lease);

        assert!(matches!(
            backend.confirm_prepared_inner(),
            Err(BackendError::ActivityNonceConflict)
        ));
        assert_eq!(backend.sign_attempts, 0);
        assert!(!backend.pending_broadcast_exists());
        assert!(
            rpc.state
                .lock()
                .expect("RPC state after conflict")
                .sent
                .is_empty()
        );
        remove_test_backend_files(&backend);
    }

    #[test]
    fn occupied_activity_nonce_slot_rejects_saved_erc20_before_sign_pending_or_send() {
        let rpc = TokenRpc::new();
        let contract = [0x73; 20];
        let mut backend = saved_token_backend(rpc.clone(), contract, 0x74);
        let active_epoch = std::sync::atomic::AtomicU64::new(0);
        let permit = SessionPermit::current_for_test(0, &active_epoch);
        backend
            .prepare_saved_erc20_transfer_inner(
                &checksum_address(contract),
                &checksum_address([0x75; 20]),
                "1.25",
                FeeSelection::Recommended,
                &permit,
            )
            .expect("prepare saved ERC20 conflict fixture");
        let PreparedTransfer::SavedErc20(prepared) = backend
            .prepared
            .as_ref()
            .expect("prepared saved ERC20 fixture")
        else {
            panic!("expected saved ERC20 prepared fixture");
        };
        let occupied = TransactionIdentity::native(
            [0x76; 32],
            prepared.sender,
            prepared.account_index,
            *prepared.nonce.as_be_bytes(),
            *prepared.gas_limit.as_be_bytes(),
            *prepared.priority_fee.as_be_bytes(),
            *prepared.maximum_fee.as_be_bytes(),
            [0x77; 20],
            *Word::from_u64(1).as_be_bytes(),
        )
        .expect("occupied saved ERC20 nonce-slot identity");
        let context = backend.activity_context().expect("v2 activity context");
        let activity_lease = ActivityMutationLease::acquire(&backend.activity_store_path)
            .expect("activity mutation lease");
        let mut loaded = backend
            .load_activity_store(&context)
            .expect("empty activity store");
        backend
            .commit_submitted_activity(&activity_lease, &context, &mut loaded, &occupied)
            .expect("commit saved ERC20 nonce-slot fixture");
        drop(activity_lease);

        assert!(matches!(
            backend.confirm_prepared_with_permit(&permit),
            Err(BackendError::ActivityNonceConflict)
        ));
        assert_eq!(backend.sign_attempts, 0);
        assert!(!backend.pending_broadcast_exists());
        assert!(rpc.state.lock().expect("token RPC state").sent.is_empty());
        remove_test_backend_files(&backend);
    }

    #[test]
    fn full_activity_store_rejects_native_and_saved_erc20_before_signing() {
        let native_rpc = MutableRpc::new();
        native_rpc.update(|state| state.nonce = Word::from_u64(1_000));
        let native_clock = TestClock::new(Instant::now());
        let mut native = unlocked_backend(native_rpc.clone(), native_clock);
        native
            .prepare_transfer_inner(
                "0x1111111111111111111111111111111111111111",
                "0.25",
                FeeSelection::Recommended,
            )
            .expect("prepare native capacity fixture");
        let (_, native_sender) = native.selected_account().expect("native sender");
        fill_activity_store_to_capacity(&native, native_sender);
        assert!(matches!(
            native.confirm_prepared_inner(),
            Err(BackendError::ActivityCapacity)
        ));
        assert_eq!(native.sign_attempts, 0);
        assert!(!native.pending_broadcast_exists());
        assert!(
            native_rpc
                .state
                .lock()
                .expect("native capacity RPC")
                .sent
                .is_empty()
        );
        remove_test_backend_files(&native);

        let token_rpc = TokenRpc::new();
        token_rpc.state.lock().expect("token capacity RPC").nonce = Word::from_u64(1_000);
        let contract = [0x7a; 20];
        let mut token = saved_token_backend(token_rpc.clone(), contract, 0x7b);
        let active_epoch = std::sync::atomic::AtomicU64::new(0);
        let permit = SessionPermit::current_for_test(0, &active_epoch);
        token
            .prepare_saved_erc20_transfer_inner(
                &checksum_address(contract),
                &checksum_address([0x7c; 20]),
                "1.25",
                FeeSelection::Recommended,
                &permit,
            )
            .expect("prepare saved ERC20 capacity fixture");
        let (_, token_sender) = token.selected_account().expect("token sender");
        fill_activity_store_to_capacity(&token, token_sender);
        assert!(matches!(
            token.confirm_prepared_with_permit(&permit),
            Err(BackendError::ActivityCapacity)
        ));
        assert_eq!(token.sign_attempts, 0);
        assert!(!token.pending_broadcast_exists());
        assert!(
            token_rpc
                .state
                .lock()
                .expect("token capacity RPC after confirm")
                .sent
                .is_empty()
        );
        remove_test_backend_files(&token);
    }

    #[test]
    fn authenticated_activity_sender_must_bind_to_vault_account_index() {
        let backend = unlocked_backend(MutableRpc::new(), TestClock::new(Instant::now()));
        let context = backend.activity_context().expect("v2 activity context");
        let mut store = ActivityStore::empty(context.vault_id).expect("empty activity store");
        let mismatched = TransactionIdentity::native(
            [0x66; 32],
            [0x77; 20],
            0,
            *Word::from_u64(1).as_be_bytes(),
            *Word::from_u64(NATIVE_TRANSFER_GAS).as_be_bytes(),
            *Word::from_u64(1_000_000_000).as_be_bytes(),
            *Word::from_u64(2_000_000_000).as_be_bytes(),
            [0x88; 20],
            *Word::from_u64(1).as_be_bytes(),
        )
        .expect("authenticated but vault-mismatched activity identity");
        store
            .upsert_submitted(&mismatched)
            .expect("insert vault-mismatched activity fixture");
        let sealed = store.seal(&context.key).expect("seal activity fixture");
        let activity_lease = ActivityMutationLease::acquire(&backend.activity_store_path)
            .expect("mismatched activity mutation lease");
        write_atomic_activity_store(
            &activity_lease,
            &backend.activity_store_path,
            sealed.as_slice(),
        )
        .expect("persist activity fixture");
        drop(activity_lease);
        assert!(matches!(
            backend.load_activity_store(&context),
            Err(BackendError::ActivityIdentityMismatch)
        ));
        remove_test_backend_files(&backend);
    }

    #[test]
    fn manual_activity_refresh_reduces_missing_inclusion_reorg_and_reappearance_safely() {
        let rpc = MutableRpc::new();
        let (mut backend, identity) = submitted_activity_backend(rpc.clone());
        let active_epoch = std::sync::atomic::AtomicU64::new(0);
        let permit = SessionPermit::current_for_test(0, &active_epoch);
        let hash_text = fixed_hex(identity.transaction_hash());

        for (head, expected) in [
            (100, ActivityStatusSnapshot::Submitted),
            (101, ActivityStatusSnapshot::Submitted),
            (164, ActivityStatusSnapshot::DroppedCandidate),
        ] {
            rpc.update(|state| {
                state.activity_head = ActivityRpcBlock {
                    number: head,
                    hash: [head as u8; 32],
                };
                state.observed_transaction = None;
                state.observed_receipt = None;
            });
            let refreshed = backend
                .refresh_activity_inner(&hash_text, &permit)
                .expect("reduce stable missing activity observation");
            assert!(refreshed.status == expected);
        }

        let mut pending_transaction = observed_transaction_for_identity(&identity);
        rpc.update(|state| {
            state.activity_head = ActivityRpcBlock {
                number: 165,
                hash: [0xa5; 32],
            };
            state.observed_transaction = Some(pending_transaction.clone());
        });
        let pending = backend
            .refresh_activity_inner(&hash_text, &permit)
            .expect("exact transaction reappearance becomes pending");
        assert!(matches!(pending.status, ActivityStatusSnapshot::Pending));

        let included_block = ActivityRpcBlock {
            number: 160,
            hash: [0xb0; 32],
        };
        pending_transaction.block = Some(included_block);
        pending_transaction.transaction_index = Some(3);
        let receipt = ActivityRpcReceipt {
            transaction_hash: *identity.transaction_hash(),
            from: *identity.sender(),
            to: *identity.transfer().recipient(),
            outcome: InclusionOutcome::Success,
            block: included_block,
            transaction_index: 3,
        };
        rpc.update(|state| {
            state.observed_transaction = Some(pending_transaction.clone());
            state.observed_receipt = Some(receipt);
            state.canonical_blocks = vec![included_block];
        });
        let included = backend
            .refresh_activity_inner(&hash_text, &permit)
            .expect("exact receipt and canonical block become included");
        assert!(matches!(
            included.status,
            ActivityStatusSnapshot::Included(ActivityInclusionSnapshot {
                outcome: ActivityInclusionOutcome::Success,
                depth: 6,
                ..
            })
        ));

        rpc.update(|state| {
            state.observed_receipt = None;
        });
        let exact_before_null = read_activity_store_file(&backend.activity_store_path)
            .expect("read activity before null receipt");
        assert!(matches!(
            backend.refresh_activity_inner(&hash_text, &permit),
            Err(BackendError::ActivityObservationInvalid)
        ));
        assert_eq!(
            read_activity_store_file(&backend.activity_store_path)
                .expect("read activity after null receipt"),
            exact_before_null
        );

        let contradictory_block = ActivityRpcBlock {
            number: 161,
            hash: [0xd0; 32],
        };
        let mut contradictory_transaction = observed_transaction_for_identity(&identity);
        contradictory_transaction.block = Some(contradictory_block);
        contradictory_transaction.transaction_index = Some(4);
        rpc.update(|state| {
            state.observed_transaction = Some(contradictory_transaction);
            state.observed_receipt = Some(ActivityRpcReceipt {
                transaction_hash: *identity.transaction_hash(),
                from: *identity.sender(),
                to: *identity.transfer().recipient(),
                outcome: InclusionOutcome::Success,
                block: contradictory_block,
                transaction_index: 4,
            });
            state.canonical_blocks = vec![included_block, contradictory_block];
        });
        let exact_before_contradiction = read_activity_store_file(&backend.activity_store_path)
            .expect("read activity before contradictory anchors");
        assert!(matches!(
            backend.refresh_activity_inner(&hash_text, &permit),
            Err(BackendError::ActivityObservationInvalid)
        ));
        assert_eq!(
            read_activity_store_file(&backend.activity_store_path)
                .expect("read activity after contradictory anchors"),
            exact_before_contradiction
        );

        rpc.update(|state| {
            state.activity_head = ActivityRpcBlock {
                number: 164,
                hash: [0xa4; 32],
            };
            state.canonical_blocks.clear();
        });
        let exact_before_shorter = read_activity_store_file(&backend.activity_store_path)
            .expect("read activity before shorter head");
        assert!(matches!(
            backend.refresh_activity_inner(&hash_text, &permit),
            Err(BackendError::ActivityObservationInvalid)
        ));
        assert_eq!(
            read_activity_store_file(&backend.activity_store_path)
                .expect("read activity after shorter head"),
            exact_before_shorter
        );

        rpc.update(|state| {
            state.activity_head = ActivityRpcBlock {
                number: 166,
                hash: [0xa6; 32],
            };
            state.observed_transaction = None;
            state.observed_receipt = None;
            state.canonical_blocks = vec![ActivityRpcBlock {
                number: included_block.number,
                hash: [0xc0; 32],
            }];
        });
        let reorged = backend
            .refresh_activity_inner(&hash_text, &permit)
            .expect("different canonical old-height hash proves reorg");
        assert!(matches!(reorged.status, ActivityStatusSnapshot::Reorged(_)));

        rpc.update(|state| {
            state.activity_head = ActivityRpcBlock {
                number: 167,
                hash: [0xa7; 32],
            };
            state.observed_transaction = Some(observed_transaction_for_identity(&identity));
        });
        let reappeared = backend
            .refresh_activity_inner(&hash_text, &permit)
            .expect("reorged exact transaction reappears as pending");
        assert!(matches!(reappeared.status, ActivityStatusSnapshot::Pending));
        remove_test_backend_files(&backend);
    }

    #[test]
    fn activity_orphan_temp_is_reconciled_before_sign_and_nonregular_temp_fails_closed() {
        let backend = unlocked_backend(MutableRpc::new(), TestClock::new(Instant::now()));
        let context = backend.activity_context().expect("v2 activity context");
        let (_, sender) = backend.selected_account().expect("selected test account");
        let identity = TransactionIdentity::native(
            [0x81; 32],
            sender,
            0,
            *Word::from_u64(1).as_be_bytes(),
            *Word::from_u64(NATIVE_TRANSFER_GAS).as_be_bytes(),
            *Word::from_u64(1_000_000_000).as_be_bytes(),
            *Word::from_u64(2_000_000_000).as_be_bytes(),
            [0x82; 20],
            *Word::from_u64(1).as_be_bytes(),
        )
        .expect("orphan recovery activity identity");
        let mut store = ActivityStore::empty(context.vault_id).expect("empty activity store");
        store
            .upsert_submitted(&identity)
            .expect("populate activity store before sealing");
        let sealed = store
            .seal(&context.key)
            .expect("seal populated activity store");
        let temporary = activity_store_temporary_path(&backend.activity_store_path)
            .expect("activity temporary path");

        for orphan in [Vec::new(), vec![0xa5; 17], sealed.clone()] {
            fs::write(&temporary, orphan).expect("write prior-crash activity temp");
            let activity_lease = ActivityMutationLease::acquire(&backend.activity_store_path)
                .expect("reconcile regular orphan before mutation");
            assert!(!path_may_exist(&temporary));
            write_atomic_activity_store(
                &activity_lease,
                &backend.activity_store_path,
                sealed.as_slice(),
            )
            .expect("install after orphan reconciliation");
            drop(activity_lease);
            assert_eq!(
                read_activity_store_file(&backend.activity_store_path)
                    .expect("read installed activity"),
                Some(sealed.clone())
            );
        }

        let installed = fs::read(&backend.activity_store_path).expect("capture installed activity");
        fs::create_dir(&temporary).expect("create nonregular reserved temp");
        assert!(matches!(
            ActivityMutationLease::acquire(&backend.activity_store_path),
            Err(BackendError::ActivityStoreInvalid | BackendError::ActivityStoreStorage)
        ));
        assert_eq!(
            fs::read(&backend.activity_store_path).expect("installed activity is untouched"),
            installed
        );
        fs::remove_dir(&temporary).expect("remove nonregular temp fixture");

        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;

            fs::write(&temporary, [0x5a]).expect("write contended orphan temp");
            let held = OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(0)
                .open(&temporary)
                .expect("hold orphan temp without sharing");
            assert!(matches!(
                ActivityMutationLease::acquire(&backend.activity_store_path),
                Err(BackendError::ActivityStoreStorage)
            ));
            assert_eq!(
                fs::read(&backend.activity_store_path).expect("contended temp cannot overwrite"),
                installed
            );
            drop(held);
            let lease = ActivityMutationLease::acquire(&backend.activity_store_path)
                .expect("released orphan is reconciled");
            assert!(!path_may_exist(&temporary));
            drop(lease);
        }
        remove_test_backend_files(&backend);
    }

    #[test]
    fn token_orphan_temp_is_reconciled_before_new_v2_or_token_mutation() {
        let backend = unlocked_backend(MutableRpc::new(), TestClock::new(Instant::now()));
        let temporary =
            token_store_temporary_path(&backend.token_store_path).expect("token temporary path");
        for orphan in [Vec::new(), vec![0xa5; 17], vec![0x5a; 512]] {
            fs::write(&temporary, orphan).expect("write prior-crash token temp");
            let lease = TokenMutationLease::acquire(&backend.token_store_path)
                .expect("reconcile regular token orphan before mutation");
            assert!(!path_may_exist(&temporary));
            drop(lease);
        }

        fs::create_dir(&temporary).expect("create nonregular token temp");
        assert!(matches!(
            TokenMutationLease::acquire(&backend.token_store_path),
            Err(BackendError::TokenStoreInvalid | BackendError::TokenStoreStorage)
        ));
        assert!(temporary.is_dir());
        fs::remove_dir(&temporary).expect("remove nonregular token temp fixture");

        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;

            fs::write(&temporary, [0x4a]).expect("write contended token temp");
            let held = OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(0)
                .open(&temporary)
                .expect("hold token temp without sharing");
            assert!(matches!(
                TokenMutationLease::acquire(&backend.token_store_path),
                Err(BackendError::TokenStoreStorage)
            ));
            drop(held);
            let lease = TokenMutationLease::acquire(&backend.token_store_path)
                .expect("released token orphan is reconciled");
            assert!(!path_may_exist(&temporary));
            drop(lease);
        }
        remove_test_backend_files(&backend);

        let mut fresh = DemoBackend::with_rpc(temporary_vault(), test_rpc());
        let parent = fresh.vault_v2_path.parent().expect("fresh wallet parent");
        fs::create_dir_all(parent).expect("create orphan-token parent");
        let temporary =
            token_store_temporary_path(&fresh.token_store_path).expect("fresh token temp");
        fs::write(&temporary, [0x2a; 33]).expect("write fresh-wallet token orphan");
        fresh
            .import_private_key(
                sensitive(&fixed_hex(&[0x45; KEY_BYTES])),
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            )
            .expect("regular token orphan is reconciled before v2 commit");
        assert!(fresh.vault_v2_path.is_file());
        assert!(!path_may_exist(&temporary));
        remove_test_backend_files(&fresh);

        let blocked_rpc = MutableRpc::new();
        let mut blocked = DemoBackend::with_rpc(temporary_vault(), blocked_rpc.clone());
        let blocked_parent = blocked.vault_v2_path.parent().expect("blocked temp parent");
        fs::create_dir_all(blocked_parent).expect("create blocked-temp parent");
        let blocked_temporary =
            token_store_temporary_path(&blocked.token_store_path).expect("blocked token temporary");
        fs::create_dir(&blocked_temporary).expect("create nonregular fresh token temp");
        assert!(
            blocked
                .import_private_key(
                    sensitive(&fixed_hex(&[0x4b; KEY_BYTES])),
                    sensitive(TEST_PASSWORD),
                    sensitive(TEST_PASSWORD),
                )
                .is_err()
        );
        assert_eq!(blocked.sign_attempts, 0);
        assert!(
            blocked_rpc
                .state
                .lock()
                .expect("blocked-temp RPC state")
                .sent
                .is_empty()
        );
        for path in [
            &blocked.vault_path,
            &blocked.vault_v2_path,
            &blocked.pending_path,
            &blocked.activity_store_path,
            &blocked.token_store_path,
        ] {
            assert!(!path_may_exist(path));
        }
        fs::remove_dir(&blocked_temporary).expect("remove nonregular fresh token temp");
        remove_test_backend_files(&blocked);

        #[cfg(windows)]
        {
            use std::os::windows::fs::{OpenOptionsExt, symlink_file};

            let contended_rpc = MutableRpc::new();
            let mut contended = DemoBackend::with_rpc(temporary_vault(), contended_rpc.clone());
            let parent = contended
                .vault_v2_path
                .parent()
                .expect("contended fresh parent");
            fs::create_dir_all(parent).expect("create contended fresh parent");
            let temporary = token_store_temporary_path(&contended.token_store_path)
                .expect("contended fresh temporary");
            fs::write(&temporary, [0x5b]).expect("write contended fresh token temp");
            let held = OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(0)
                .open(&temporary)
                .expect("hold fresh token temp");
            assert!(
                contended
                    .import_private_key(
                        sensitive(&fixed_hex(&[0x4c; KEY_BYTES])),
                        sensitive(TEST_PASSWORD),
                        sensitive(TEST_PASSWORD),
                    )
                    .is_err()
            );
            assert_eq!(contended.sign_attempts, 0);
            assert!(
                contended_rpc
                    .state
                    .lock()
                    .expect("contended RPC state")
                    .sent
                    .is_empty()
            );
            assert!(!path_may_exist(&contended.vault_v2_path));
            drop(held);
            fs::remove_file(&temporary).expect("remove contended fresh token temp");
            remove_test_backend_files(&contended);

            let reparse_rpc = MutableRpc::new();
            let mut reparse = DemoBackend::with_rpc(temporary_vault(), reparse_rpc.clone());
            let parent = reparse
                .vault_v2_path
                .parent()
                .expect("reparse fresh parent");
            fs::create_dir_all(parent).expect("create reparse fresh parent");
            let temporary = token_store_temporary_path(&reparse.token_store_path)
                .expect("reparse fresh temporary");
            let target = parent.join("token-temp-reparse-target");
            fs::write(&target, [0x6b]).expect("write reparse target");
            if symlink_file(&target, &temporary).is_ok() {
                assert!(
                    reparse
                        .import_private_key(
                            sensitive(&fixed_hex(&[0x4d; KEY_BYTES])),
                            sensitive(TEST_PASSWORD),
                            sensitive(TEST_PASSWORD),
                        )
                        .is_err()
                );
                assert_eq!(reparse.sign_attempts, 0);
                assert!(
                    reparse_rpc
                        .state
                        .lock()
                        .expect("reparse RPC state")
                        .sent
                        .is_empty()
                );
                assert!(!path_may_exist(&reparse.vault_v2_path));
                fs::remove_file(&temporary).expect("remove token temp reparse point");
            }
            fs::remove_file(&target).expect("remove token temp reparse target");
            remove_test_backend_files(&reparse);
        }
    }

    #[test]
    fn fresh_v2_parent_is_created_durably_and_invalid_parent_fails_before_vault_write() {
        let mut fresh = DemoBackend::with_rpc(temporary_vault(), test_rpc());
        let parent = fresh
            .vault_v2_path
            .parent()
            .expect("fresh namespace parent")
            .to_path_buf();
        assert!(!path_may_exist(&parent));
        fresh
            .import_private_key(
                sensitive(&fixed_hex(&[0x46; KEY_BYTES])),
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            )
            .expect("create first-run namespace and v2 vault");
        assert!(parent.is_dir());
        assert!(fresh.vault_v2_path.is_file());
        remove_test_backend_files(&fresh);

        let first_level = temporary_vault()
            .parent()
            .expect("production-shaped first level")
            .to_path_buf();
        let second_level = first_level.join("SepoliaDemo");
        let mut two_level = DemoBackend::with_rpc(second_level.join("vault-v1.bin"), test_rpc());
        assert!(!path_may_exist(&first_level));
        two_level
            .import_private_key(
                sensitive(&fixed_hex(&[0x49; KEY_BYTES])),
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            )
            .expect("durably create two fixed first-run namespace levels");
        assert!(first_level.is_dir());
        assert!(second_level.is_dir());
        assert!(two_level.vault_v2_path.is_file());
        remove_test_backend_files(&two_level);
        fs::remove_dir(&first_level).expect("remove first namespace level");

        for preexisting_levels in [1_u8, 2] {
            let first_level = temporary_vault()
                .parent()
                .expect("crash-retry first level")
                .to_path_buf();
            let second_level = first_level.join("SepoliaDemo");
            fs::create_dir(&first_level).expect("simulate pre-flush first-level mkdir");
            if preexisting_levels == 2 {
                fs::create_dir(&second_level).expect("simulate pre-flush second-level mkdir");
            }
            let mut retry = DemoBackend::with_rpc(second_level.join("vault-v1.bin"), test_rpc());
            retry
                .import_private_key(
                    sensitive(&fixed_hex(&[0x4a; KEY_BYTES])),
                    sensitive(TEST_PASSWORD),
                    sensitive(TEST_PASSWORD),
                )
                .expect("reflush pre-existing namespace entries before vault commit");
            assert!(retry.vault_v2_path.is_file());
            remove_test_backend_files(&retry);
            fs::remove_dir(&first_level).expect("remove crash-retry first level");
        }

        let mut invalid = DemoBackend::with_rpc(temporary_vault(), test_rpc());
        let invalid_parent = invalid
            .vault_v2_path
            .parent()
            .expect("invalid namespace parent")
            .to_path_buf();
        fs::write(&invalid_parent, b"not a directory").expect("write invalid parent fixture");
        assert!(
            invalid
                .import_private_key(
                    sensitive(&fixed_hex(&[0x47; KEY_BYTES])),
                    sensitive(TEST_PASSWORD),
                    sensitive(TEST_PASSWORD),
                )
                .is_err()
        );
        assert!(invalid.unlocked.is_none());
        assert!(!path_may_exist(&invalid.vault_v2_path));
        fs::remove_file(&invalid_parent).expect("remove invalid parent fixture");

        #[cfg(windows)]
        {
            use std::os::windows::fs::symlink_dir;

            let mut reparse = DemoBackend::with_rpc(temporary_vault(), test_rpc());
            let reparse_parent = reparse
                .vault_v2_path
                .parent()
                .expect("reparse namespace parent")
                .to_path_buf();
            let target = reparse_parent.parent().expect("reparse target grandparent");
            if symlink_dir(target, &reparse_parent).is_ok() {
                assert!(
                    reparse
                        .import_private_key(
                            sensitive(&fixed_hex(&[0x48; KEY_BYTES])),
                            sensitive(TEST_PASSWORD),
                            sensitive(TEST_PASSWORD),
                        )
                        .is_err()
                );
                assert!(reparse.unlocked.is_none());
                assert!(!path_may_exist(&reparse.vault_v2_path));
                fs::remove_dir(&reparse_parent).expect("remove reparse parent fixture");
            }
        }
    }

    #[test]
    fn invalid_activity_sidecar_locks_open_and_stale_sidecars_block_new_v2_commit() {
        let mut backend = DemoBackend::with_rpc(temporary_vault(), test_rpc());
        backend
            .import_private_key(
                sensitive(&fixed_hex(&[0x42; KEY_BYTES])),
                sensitive(TEST_PASSWORD),
                sensitive(TEST_PASSWORD),
            )
            .expect("create valid v2 fixture");
        let context = backend.activity_context().expect("activity context");
        let (_, sender) = backend.selected_account().expect("selected test account");
        let identity = TransactionIdentity::native(
            [0x83; 32],
            sender,
            0,
            *Word::from_u64(1).as_be_bytes(),
            *Word::from_u64(NATIVE_TRANSFER_GAS).as_be_bytes(),
            *Word::from_u64(1_000_000_000).as_be_bytes(),
            *Word::from_u64(2_000_000_000).as_be_bytes(),
            [0x84; 20],
            *Word::from_u64(1).as_be_bytes(),
        )
        .expect("wrong-vault activity identity");
        let mut wrong_vault = ActivityStore::empty([0x99; 16]).expect("wrong-vault activity");
        wrong_vault
            .upsert_submitted(&identity)
            .expect("populate wrong-vault activity store");
        let sealed = wrong_vault
            .seal(&context.key)
            .expect("seal authenticated wrong-vault activity");
        let activity_lease = ActivityMutationLease::acquire(&backend.activity_store_path)
            .expect("wrong-vault activity lease");
        write_atomic_activity_store(
            &activity_lease,
            &backend.activity_store_path,
            sealed.as_slice(),
        )
        .expect("persist wrong-vault activity fixture");
        drop(activity_lease);
        backend.lock();
        assert!(backend.open(TEST_PASSWORD).is_err());
        assert!(backend.unlocked.is_none());
        assert!(matches!(
            backend.prepare_transfer_inner(
                "0x1111111111111111111111111111111111111111",
                "0.25",
                FeeSelection::Recommended,
            ),
            Err(BackendError::Locked)
        ));
        assert!(matches!(
            backend.export_account_private_key_inner(sensitive(TEST_PASSWORD)),
            Err(BackendError::Locked)
        ));
        remove_test_backend_files(&backend);

        for sidecar in ["activity", "token"] {
            let mut fresh = DemoBackend::with_rpc(temporary_vault(), test_rpc());
            let parent = fresh.vault_v2_path.parent().expect("new-v2 parent");
            fs::create_dir_all(parent).expect("create new-v2 parent");
            let path = if sidecar == "activity" {
                &fresh.activity_store_path
            } else {
                &fresh.token_store_path
            };
            fs::write(path, [0x7e]).expect("write stale sidecar fixture");
            assert!(
                fresh
                    .import_private_key(
                        sensitive(&fixed_hex(&[0x43; KEY_BYTES])),
                        sensitive(TEST_PASSWORD),
                        sensitive(TEST_PASSWORD),
                    )
                    .is_err()
            );
            assert!(fresh.unlocked.is_none());
            assert!(!path_may_exist(&fresh.vault_v2_path));
            remove_test_backend_files(&fresh);
        }
    }

    #[test]
    fn migration_temp_crash_recovery_pins_install_and_preserves_pending_until_commit() {
        let backend = DemoBackend::with_rpc(temporary_vault(), test_rpc());
        let mut legacy_key = [0_u8; KEY_BYTES];
        legacy_key.fill(0x54);
        write_legacy_fixture(&backend, TEST_PASSWORD, 0x54);
        let sender = address_from_private_key(&legacy_key).expect("legacy sender");
        let signed = sign_native_type_two(
            &legacy_key,
            sender,
            [0x55; 20],
            Word::from_u64(1),
            Word::from_u64(7),
            Word::from_u64(NATIVE_TRANSFER_GAS),
            Word::from_u64(1_000_000_000),
            Word::from_u64(2_000_000_000),
        )
        .expect("signed pending migration fixture");
        write_new_pending(
            &backend.pending_path,
            signed.transaction_hash,
            signed.bytes.as_slice(),
        )
        .expect("write pending migration fixture");
        let pending_before = fs::read(&backend.pending_path).expect("capture exact pending");
        let legacy_before = fs::read(&backend.vault_path).expect("capture exact v1");

        let wallet = WalletSecret::from_raw_private_key_bytes(Zeroizing::new(legacy_key))
            .expect("v2 migration wallet");
        let password = matching_vault_password(sensitive(TEST_PASSWORD), sensitive(TEST_PASSWORD))
            .expect("v2 migration password");
        let metadata = confirmed_metadata(VaultOrigin::MigratedV1RawPrivateKey)
            .expect("v2 migration metadata");
        let sealed = seal_vault_v2(&wallet, &password, metadata).expect("seal migration v2");
        let temporary = vault_v2_migration_temporary_path(&backend.vault_v2_path)
            .expect("migration temporary path");
        fs::write(&temporary, [0x11; 23]).expect("simulate partial crash temp");

        let mut legacy_lease =
            LegacyVaultMigrationLease::open(&backend.vault_path).expect("pin exact v1");
        assert_eq!(
            legacy_lease.read_exact().expect("read held v1").as_slice(),
            legacy_before.as_slice()
        );
        let uncommitted =
            CreatedV2VaultMigrationLease::create(&backend.vault_v2_path, sealed.as_bytes())
                .expect("reconcile crash temp and create exact temp");
        assert!(path_may_exist(&temporary));
        assert!(!path_may_exist(&backend.vault_v2_path));
        drop(uncommitted);
        assert!(!path_may_exist(&temporary));
        assert!(!path_may_exist(&backend.vault_v2_path));
        assert_eq!(
            fs::read(&backend.pending_path).expect("pending survives abort"),
            pending_before
        );

        let mut installed =
            CreatedV2VaultMigrationLease::create(&backend.vault_v2_path, sealed.as_bytes())
                .expect("create exact authenticated migration temp");
        installed
            .verify_exact(sealed.as_bytes())
            .expect("exact temp readback");
        open_vault_v2(
            installed
                .read_exact()
                .expect("read temp for auth")
                .as_slice(),
            &password,
        )
        .expect("authenticate temp before install");
        installed
            .install_exact(&backend.vault_v2_path)
            .expect("same-handle final install");
        installed
            .verify_exact(sealed.as_bytes())
            .expect("same-handle installed readback");
        installed
            .mark_committed()
            .expect("mark installed v2 committed");
        legacy_lease
            .delete_exact(&backend.vault_path)
            .expect("delete exact held v1");
        assert!(!path_may_exist(&backend.vault_path));
        assert_eq!(
            fs::read(&backend.pending_path).expect("pending survives v1 cleanup"),
            pending_before
        );
        drop(installed);
        drop(legacy_lease);
        assert_eq!(
            fs::read(&backend.vault_v2_path).expect("read installed v2"),
            sealed.as_bytes()
        );
        remove_test_backend_files(&backend);
    }

    #[cfg(windows)]
    #[test]
    fn windows_migration_leases_pin_v1_temp_and_installed_v2_exact_objects() {
        let backend = DemoBackend::with_rpc(temporary_vault(), test_rpc());
        let mut legacy_key = [0_u8; KEY_BYTES];
        legacy_key.fill(0x57);
        write_legacy_fixture(&backend, TEST_PASSWORD, 0x57);
        let legacy_before = fs::read(&backend.vault_path).expect("capture exact legacy vault");

        let wallet = WalletSecret::from_raw_private_key_bytes(Zeroizing::new(legacy_key))
            .expect("construct migration wallet");
        let password = matching_vault_password(sensitive(TEST_PASSWORD), sensitive(TEST_PASSWORD))
            .expect("migration password");
        let metadata =
            confirmed_metadata(VaultOrigin::MigratedV1RawPrivateKey).expect("migration metadata");
        let sealed = seal_vault_v2(&wallet, &password, metadata).expect("seal migration v2");
        let parent = backend.vault_path.parent().expect("migration parent");
        let legacy_rename = parent.join("competing-vault-v1-rename");
        let temp_rename = parent.join("competing-vault-v2-temp-rename");
        let final_rename = parent.join("competing-vault-v2-final-rename");
        assert!(!path_may_exist(&legacy_rename));
        assert!(!path_may_exist(&temp_rename));
        assert!(!path_may_exist(&final_rename));

        let mut legacy =
            LegacyVaultMigrationLease::open(&backend.vault_path).expect("hold exact legacy v1");
        let legacy_identity =
            windows_file_identity(legacy.file.as_ref().expect("held exact legacy v1 handle"));
        assert!(File::open(&backend.vault_path).is_err());
        assert!(
            OpenOptions::new()
                .write(true)
                .open(&backend.vault_path)
                .is_err()
        );
        assert!(fs::remove_file(&backend.vault_path).is_err());
        assert!(fs::rename(&backend.vault_path, &legacy_rename).is_err());
        assert_eq!(
            windows_file_identity(legacy.file.as_ref().expect("legacy handle remains held")),
            legacy_identity
        );
        assert_eq!(
            legacy.read_exact().expect("held legacy bytes").as_slice(),
            legacy_before.as_slice()
        );

        let temporary = vault_v2_migration_temporary_path(&backend.vault_v2_path)
            .expect("migration temporary path");
        let mut installed =
            CreatedV2VaultMigrationLease::create(&backend.vault_v2_path, sealed.as_bytes())
                .expect("create held migration temp");
        let temporary_identity = windows_file_identity(
            installed
                .file
                .as_ref()
                .expect("held exact migration temp handle"),
        );
        assert!(File::open(&temporary).is_err());
        assert!(OpenOptions::new().write(true).open(&temporary).is_err());
        assert!(fs::remove_file(&temporary).is_err());
        assert!(fs::rename(&temporary, &temp_rename).is_err());
        installed
            .verify_exact(sealed.as_bytes())
            .expect("held migration temp remains exact");

        installed
            .install_exact(&backend.vault_v2_path)
            .expect("same-handle install migration v2");
        assert!(!path_may_exist(&temporary));
        assert_eq!(
            windows_file_identity(installed.file.as_ref().expect("held installed v2 handle")),
            temporary_identity
        );
        assert!(File::open(&backend.vault_v2_path).is_err());
        assert!(
            OpenOptions::new()
                .write(true)
                .open(&backend.vault_v2_path)
                .is_err()
        );
        assert!(fs::remove_file(&backend.vault_v2_path).is_err());
        assert!(fs::rename(&backend.vault_v2_path, &final_rename).is_err());
        installed
            .verify_exact(sealed.as_bytes())
            .expect("held installed v2 remains exact");

        installed
            .mark_committed()
            .expect("commit exact installed v2");
        legacy
            .delete_exact(&backend.vault_path)
            .expect("delete exact held legacy v1");
        assert!(!path_may_exist(&backend.vault_path));
        drop(legacy);
        let installed_identity = windows_file_identity(
            installed
                .file
                .as_ref()
                .expect("installed handle remains pinned"),
        );
        assert_eq!(installed_identity, temporary_identity);
        drop(installed);

        let reopened = File::open(&backend.vault_v2_path).expect("reopen installed v2 after lease");
        assert_eq!(windows_file_identity(&reopened), temporary_identity);
        drop(reopened);
        assert_eq!(
            fs::read(&backend.vault_v2_path).expect("read exact installed v2"),
            sealed.as_bytes()
        );
        remove_test_backend_files(&backend);
    }

    #[test]
    fn stale_or_nonregular_sidecars_block_legacy_migration_before_vault_mutation() {
        for kind in ["activity", "token", "activity-directory"] {
            let mut backend = DemoBackend::with_rpc(temporary_vault(), test_rpc());
            write_legacy_fixture(&backend, TEST_PASSWORD, 0x61);
            let legacy_before = fs::read(&backend.vault_path).expect("capture legacy bytes");
            let sidecar = if kind.starts_with("activity") {
                &backend.activity_store_path
            } else {
                &backend.token_store_path
            };
            if kind == "activity-directory" {
                fs::create_dir(sidecar).expect("create nonregular sidecar");
            } else {
                fs::write(sidecar, [0x33]).expect("create stale sidecar");
            }
            assert!(
                backend
                    .migrate_legacy(
                        sensitive(TEST_PASSWORD),
                        sensitive("new-migration-password"),
                        sensitive("new-migration-password"),
                    )
                    .is_err()
            );
            assert_eq!(
                fs::read(&backend.vault_path).expect("legacy remains exact"),
                legacy_before
            );
            assert!(!path_may_exist(&backend.vault_v2_path));
            assert!(
                vault_v2_migration_temporary_path(&backend.vault_v2_path)
                    .is_ok_and(|path| !path_may_exist(&path))
            );
            remove_test_backend_files(&backend);
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
