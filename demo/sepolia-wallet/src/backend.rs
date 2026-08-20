//! Secret-bearing backend for the standalone Sepolia development wallet.
//!
//! This module is deliberately independent from the production vault and
//! authorization formats. It supports one generated key, one fixed testnet,
//! and native EIP-1559 transfers only. There is no key import/export API.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

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
use crate::ui::{SendReceipt, TransferPreview, WalletBackend, WalletSnapshot};

const NATIVE_TRANSFER_GAS: u64 = 21_000;
const MAX_TRANSFER_WEI: u64 = 10_000_000_000_000_000_000;
const MAX_PRIORITY_FEE_PER_GAS: u64 = 10_000_000_000;
const MAX_FEE_PER_GAS: u64 = 100_000_000_000;

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
    vault_path: PathBuf,
    pending_path: PathBuf,
    rpc: Box<dyn RpcAccess>,
    unlocked: Option<UnlockedWallet>,
    last_balance: Option<Word>,
    prepared: Option<PreparedTransfer>,
}

struct UnlockedWallet {
    private_key: Zeroizing<[u8; KEY_BYTES]>,
    address: [u8; 20],
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
    priority_fee: Word,
    maximum_fee: Word,
    maximum_network_fee: Word,
    maximum_spend: Word,
}

trait RpcAccess: Send {
    fn verify_sepolia(&self) -> Result<(), ()>;
    fn balance(&self, address: [u8; 20]) -> Result<Word, ()>;
    fn pending_nonce(&self, address: [u8; 20]) -> Result<Word, ()>;
    fn fee_quote(&self) -> Result<(Word, Word), ()>;
    fn send_raw_transaction(&self, signed: &[u8]) -> Result<[u8; 32], ()>;
}

impl DemoBackend {
    /// Constructs the fixed-endpoint Sepolia backend without touching the vault.
    pub fn new() -> Result<Self, String> {
        let local_data = std::env::var_os("LOCALAPPDATA")
            .ok_or_else(|| error_text(BackendError::StorageUnavailable))?;
        let vault_path = PathBuf::from(local_data)
            .join("YourWallet")
            .join("SepoliaDemo")
            .join("vault-v1.bin");
        let pending_path = sibling_pending_path(&vault_path)?;
        let rpc = rpc::SepoliaRpc::new();
        Ok(Self {
            vault_path,
            pending_path,
            rpc: Box::new(LiveRpc(rpc)),
            unlocked: None,
            last_balance: None,
            prepared: None,
        })
    }

    #[cfg(test)]
    fn with_rpc(vault_path: PathBuf, rpc: impl RpcAccess + 'static) -> Self {
        let pending_path = vault_path.with_file_name("pending-v1.bin");
        Self {
            vault_path,
            pending_path,
            rpc: Box::new(rpc),
            unlocked: None,
            last_balance: None,
            prepared: None,
        }
    }

    /// Returns whether the separate disposable testnet vault exists.
    #[must_use]
    pub fn wallet_exists(&self) -> bool {
        self.vault_path.is_file()
    }

    /// Reports a prior signed transaction whose broadcast result was not
    /// durably resolved. A new transaction is never signed while this is true.
    #[must_use]
    pub fn pending_broadcast_exists(&self) -> bool {
        self.pending_path.is_file()
    }

    /// Immediately forgets the unlocked key and cached balance.
    #[cfg(test)]
    pub fn lock(&mut self) {
        self.prepared = None;
        self.unlocked = None;
        self.last_balance = None;
    }

    /// Returns the current public address, if the vault is unlocked.
    #[must_use]
    #[cfg(test)]
    pub fn address(&self) -> Option<String> {
        self.unlocked
            .as_ref()
            .map(|wallet| checksum_address(wallet.address))
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
        let balance_eth = self
            .last_balance
            .map_or_else(|| "조회 전".to_owned(), format_ether);
        Ok(WalletSnapshot {
            address: checksum_address(wallet.address),
            balance_eth,
        })
    }

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

        self.unlocked = Some(UnlockedWallet {
            private_key,
            address,
        });
        self.last_balance = Some(Word::ZERO);
        self.snapshot()
    }

    fn open(&mut self, password: &str) -> Result<WalletSnapshot, BackendError> {
        self.prepared = None;
        validate_password(password)?;
        let bytes = read_vault(&self.vault_path)?;
        let private_key = open_vault(bytes.as_slice(), password)?;
        let address = address_from_private_key(&private_key)?;
        self.unlocked = Some(UnlockedWallet {
            private_key,
            address,
        });
        self.last_balance = None;
        self.snapshot()
    }

    fn refresh_snapshot(&mut self) -> Result<WalletSnapshot, BackendError> {
        self.prepared = None;
        let address = self.unlocked.as_ref().ok_or(BackendError::Locked)?.address;
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
    ) -> Result<TransferPreview, BackendError> {
        // A second preparation invalidates the first before any fallible work.
        // Failed re-preparation therefore cannot leave a stale confirmation.
        self.prepared = None;
        let wallet = self.unlocked.as_ref().ok_or(BackendError::Locked)?;
        if self.pending_broadcast_exists() {
            return Err(BackendError::PendingExists);
        }
        let sender = wallet.address;
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
        let (priority_fee, maximum_fee) = self
            .rpc
            .fee_quote()
            .map_err(|()| BackendError::RpcUnavailable)?;
        validate_fee_quote(priority_fee, maximum_fee)?;
        let balance = self
            .rpc
            .balance(sender)
            .map_err(|()| BackendError::BalanceUnavailable)?;
        let maximum_network_fee = maximum_fee
            .checked_mul_u64(NATIVE_TRANSFER_GAS)
            .ok_or(BackendError::FeeLimit)?;
        let maximum_spend = value
            .checked_add(maximum_network_fee)
            .ok_or(BackendError::FeeLimit)?;
        if maximum_spend > balance {
            return Err(BackendError::InsufficientBalance);
        }

        let preview = TransferPreview {
            recipient: checksum_address(recipient),
            amount_eth: format_ether(value),
            nonce: decimal_string(nonce),
            max_priority_fee_per_gas_gwei: format_gwei(priority_fee),
            max_fee_per_gas_gwei: format_gwei(maximum_fee),
            max_network_fee_eth: format_ether(maximum_network_fee),
            max_total_eth: format_ether(maximum_spend),
        };
        self.prepared = Some(PreparedTransfer {
            sender,
            recipient,
            value,
            nonce,
            priority_fee,
            maximum_fee,
            maximum_network_fee,
            maximum_spend,
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
        if wallet.address != prepared.sender
            || prepared.recipient == [0; 20]
            || prepared.value.is_zero()
            || prepared.value > Word::from_u64(MAX_TRANSFER_WEI)
            || validate_fee_quote(prepared.priority_fee, prepared.maximum_fee).is_err()
            || prepared.maximum_fee.checked_mul_u64(NATIVE_TRANSFER_GAS)
                != Some(prepared.maximum_network_fee)
            || prepared.value.checked_add(prepared.maximum_network_fee)
                != Some(prepared.maximum_spend)
        {
            return Err(BackendError::PreparedInvalid);
        }
        self.rpc
            .verify_sepolia()
            .map_err(|()| BackendError::RpcUnavailable)?;
        let signed = sign_native_type_two(
            &wallet.private_key,
            prepared.sender,
            prepared.recipient,
            prepared.value,
            prepared.nonce,
            prepared.priority_fee,
            prepared.maximum_fee,
        )?;
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
    fn create_wallet(&mut self, password: &str) -> Result<WalletSnapshot, String> {
        self.create(password).map_err(error_text)
    }

    fn open_wallet(&mut self, password: &str) -> Result<WalletSnapshot, String> {
        self.open(password).map_err(error_text)
    }

    fn refresh(&mut self) -> Result<WalletSnapshot, String> {
        self.refresh_snapshot().map_err(error_text)
    }

    fn prepare_transfer(
        &mut self,
        recipient: &str,
        amount_eth: &str,
    ) -> Result<TransferPreview, String> {
        self.prepare_transfer_inner(recipient, amount_eth)
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

    fn pending_nonce(&self, address: [u8; 20]) -> Result<Word, ()> {
        self.0
            .pending_nonce(rpc::Address20::new(address))
            .map(|value| Word::from_be_bytes(*value.as_be_bytes()))
            .map_err(|_| ())
    }

    fn fee_quote(&self) -> Result<(Word, Word), ()> {
        self.0
            .fee_quote()
            .map(|quote| {
                (
                    Word::from_be_bytes(*quote.max_priority_fee_per_gas.as_be_bytes()),
                    Word::from_be_bytes(*quote.max_fee_per_gas.as_be_bytes()),
                )
            })
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
    InvalidPassword,
    VaultAuthentication,
    VaultInvalid,
    RandomnessUnavailable,
    CryptographicFailure,
    Locked,
    RpcUnavailable,
    BalanceUnavailable,
    InvalidAddress,
    InvalidAmount,
    AmountLimit,
    FeeLimit,
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
            Self::InvalidPassword => "BackendError::InvalidPassword",
            Self::VaultAuthentication => "BackendError::VaultAuthentication",
            Self::VaultInvalid => "BackendError::VaultInvalid",
            Self::RandomnessUnavailable => "BackendError::RandomnessUnavailable",
            Self::CryptographicFailure => "BackendError::CryptographicFailure",
            Self::Locked => "BackendError::Locked",
            Self::RpcUnavailable => "BackendError::RpcUnavailable",
            Self::BalanceUnavailable => "BackendError::BalanceUnavailable",
            Self::InvalidAddress => "BackendError::InvalidAddress",
            Self::InvalidAmount => "BackendError::InvalidAmount",
            Self::AmountLimit => "BackendError::AmountLimit",
            Self::FeeLimit => "BackendError::FeeLimit",
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
        BackendError::InvalidPassword => "비밀번호 형식이 올바르지 않습니다.".to_owned(),
        BackendError::VaultAuthentication => {
            "비밀번호가 틀렸거나 지갑 파일이 손상되었습니다.".to_owned()
        }
        BackendError::VaultInvalid => "지갑 파일 형식이 올바르지 않습니다.".to_owned(),
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
        BackendError::FeeLimit => "현재 수수료가 데모 안전 한도를 넘었습니다.".to_owned(),
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

fn validate_password(password: &str) -> Result<(), BackendError> {
    if !(MINIMUM_PASSWORD_BYTES..=MAXIMUM_PASSWORD_BYTES).contains(&password.len())
        || password.chars().any(char::is_control)
    {
        return Err(BackendError::InvalidPassword);
    }
    Ok(())
}

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

fn fill_random_nonzero(bytes: &mut [u8]) -> Result<(), BackendError> {
    for _ in 0..4 {
        getrandom::fill(bytes).map_err(|_| BackendError::RandomnessUnavailable)?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(());
        }
    }
    Err(BackendError::RandomnessUnavailable)
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
    if maximum_fee.is_zero()
        || maximum_fee < priority_fee
        || priority_fee > Word::from_u64(MAX_PRIORITY_FEE_PER_GAS)
        || maximum_fee > Word::from_u64(MAX_FEE_PER_GAS)
    {
        return Err(BackendError::FeeLimit);
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
    priority_fee: Word,
    maximum_fee: Word,
) -> Result<SignedTransaction, BackendError> {
    validate_fee_quote(priority_fee, maximum_fee)?;
    let chain_id = Word::from_u64(rpc::SEPOLIA_CHAIN_ID);
    let gas_limit = Word::from_u64(NATIVE_TRANSFER_GAS);
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

    const TEST_PASSWORD: &str = "correct demo password";

    struct TestRpc {
        balance: Word,
        nonce: Word,
        priority: Word,
        maximum: Word,
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

        fn pending_nonce(&self, _address: [u8; 20]) -> Result<Word, ()> {
            Ok(self.nonce)
        }

        fn fee_quote(&self) -> Result<(Word, Word), ()> {
            Ok((self.priority, self.maximum))
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
            priority: Word::from_u64(1_000_000_000),
            maximum: Word::from_u64(2_000_000_000),
            returned_hash: None,
            send_fails: false,
        }
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
            .prepare_transfer_inner(&recipient_input, &amount_input)
            .expect("prepare native transfer");
        assert_eq!(preview.recipient, checksum_address([0x11; 20]));
        assert_eq!(preview.amount_eth, "0.25");
        assert_eq!(preview.nonce, "7");
        assert_eq!(preview.max_priority_fee_per_gas_gwei, "1");
        assert_eq!(preview.max_fee_per_gas_gwei, "2");
        assert_eq!(preview.max_network_fee_eth, "0.000042");
        assert_eq!(preview.max_total_eth, "0.250042");
        assert!(!backend.pending_broadcast_exists());

        let prepared = backend.prepared.as_ref().expect("prepared object");
        let expected = sign_native_type_two(
            &backend
                .unlocked
                .as_ref()
                .expect("unlocked wallet")
                .private_key,
            prepared.sender,
            prepared.recipient,
            prepared.value,
            prepared.nonce,
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
        preview.max_priority_fee_per_gas_gwei = "9".to_owned();
        preview.max_fee_per_gas_gwei = "99".to_owned();
        preview.max_network_fee_eth = "9".to_owned();
        preview.max_total_eth = "10".to_owned();
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
    fn ambiguous_broadcast_blocks_new_signing_and_exact_retry_clears_it() {
        let vault = temporary_vault();
        let pending = vault.with_file_name("pending-v1.bin");
        let mut failing_rpc = test_rpc();
        failing_rpc.send_fails = true;
        let mut backend = DemoBackend::with_rpc(vault.clone(), failing_rpc);
        backend.create(TEST_PASSWORD).expect("create wallet");
        let recipient = "0x1111111111111111111111111111111111111111";
        backend
            .prepare_transfer_inner(recipient, "0.25")
            .expect("prepare transfer");
        assert!(matches!(
            backend.confirm_prepared_inner(),
            Err(BackendError::BroadcastUnknown)
        ));
        assert!(backend.pending_broadcast_exists());
        assert!(matches!(
            backend.prepare_transfer_inner(recipient, "0.25"),
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
            .prepare_transfer_inner("0x1111111111111111111111111111111111111111", "0.25")
            .expect("prepare transfer");
        backend.cancel_prepared_inner();
        assert!(matches!(
            backend.confirm_prepared_inner(),
            Err(BackendError::NoPreparedTransfer)
        ));

        backend
            .prepare_transfer_inner("0x1111111111111111111111111111111111111111", "0.25")
            .expect("prepare again");
        assert!(backend.prepare_transfer_inner("invalid", "1").is_err());
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
