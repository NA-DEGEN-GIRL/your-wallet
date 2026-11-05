//! vault v3 (D7, D10; spec/02 §4–§10): KEK/DEK byte format, sidecar envelopes, the storage and
//! locked-slot contracts, and the lock state machine with backup confirmation.
//!
//! Patterns ported from `archive/spec-v2.4:crates/secret-core/src/vault.rs` (header AAD, exact
//! parameter rejection, `Cursor`, record codec, backup comparison) and `storage.rs` (generation
//! CAS); the v3 layout itself is new.
#![deny(clippy::indexing_slicing)]

use core::fmt;

pub use crate::error::{StorageError, VaultError};

mod format;
mod session;

pub use format::{check_vault_header, peek_generation};
pub use session::{HardwareKey, ImportedKeys, PasswordChange, SidecarContents, Vault};

/// `vault.ywv` magic.
pub const VAULT_MAGIC: [u8; 8] = *b"YWVLT003";
/// Format version.
pub const VAULT_VERSION: u16 = 3;
/// Header length in bytes.
pub const VAULT_HEADER_LEN: usize = 176;
/// The DEK wrap AAD is `header[0..KEY_BLOCK_END]`.
pub const KEY_BLOCK_END: usize = 82;
/// A payload rewrite keeps `header[0..KEY_SECTION_END]` unchanged.
pub const KEY_SECTION_END: usize = 130;
/// KDF identifier: Argon2id v0x13.
pub const KDF_ID_ARGON2ID_V13: u16 = 1;
/// Production Argon2id parameters (256 MiB, t = 3, p = 4). Files must match exactly.
pub const KDF_V3: KdfParams = KdfParams {
    m_kib: 262_144,
    t: 3,
    p: 4,
};
/// HKDF salt for the KEK.
pub const HKDF_KEK_SALT: &[u8] = b"your-wallet/v3/kdf";
/// HKDF info for the KEK.
pub const HKDF_KEK_INFO: &[u8] = b"your-wallet/v3/kek";
/// DEK length.
pub const DEK_LEN: usize = 32;
/// Wrapped DEK length (32 + tag 16).
pub const WRAPPED_DEK_LEN: usize = 48;
/// Smallest payload ciphertext (64-byte plaintext + tag).
pub const PAYLOAD_CT_MIN: u32 = 80;
/// Largest payload ciphertext: 16 + 64 (24-word `Bip39`) + 15 × (57 + 89 + 60) imported keys
/// plus 8 × (25 + 12 + 24 × 48) hardware key references (spec/10 §8) plus the 16-byte tag is
/// 12,698 bytes; files written before key import never exceed 2,048, before hardware keys 4,096.
pub const PAYLOAD_CT_MAX: u32 = 16_384;
/// At most one `Bip39` record plus at most 15 imported keys of each chain (`EvmRawKey`,
/// `SolKey`, `BtcKey`) and 8 hardware key references (`HwKey`).
pub const MAX_RECORDS: usize = 54;
/// Locked slot layout: `[0..32)` DEK, `[32]` passphrase present, `[33..35)` passphrase length
/// (u16 BE, 0..=256), `[35..291)` passphrase bytes, `[291..320)` zero.
pub const SLOT_LEN: usize = 320;
/// `meta.ywm` magic.
pub const META_MAGIC: [u8; 8] = *b"YWMETA03";
/// `journal.ywj` magic.
pub const JOURNAL_MAGIC: [u8; 8] = *b"YWJRNL03";
/// Sidecar header length.
pub const SIDECAR_HEADER_LEN: usize = 64;
/// Largest meta plaintext (8 MiB).
pub const META_MAX_PLAINTEXT: usize = 8 * 1_024 * 1_024;
/// Largest journal plaintext (16 MiB).
pub const JOURNAL_MAX_PLAINTEXT: usize = 16 * 1_024 * 1_024;

/// Argon2id parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Iterations.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

/// The three persisted files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    /// `vault.ywv`.
    Vault,
    /// `meta.ywm`.
    Meta,
    /// `journal.ywj`.
    Journal,
}

/// Durable storage for the three files (spec/02 §6.2), implemented by yw-app over yw-win.
pub trait VaultStorage: Send {
    /// Reads the main file, `None` if absent.
    ///
    /// # Errors
    ///
    /// A [`StorageError`] for I/O failures.
    fn load(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError>;
    /// Reads `<name>.prev`, `None` if absent.
    ///
    /// # Errors
    ///
    /// A [`StorageError`] for I/O failures.
    fn load_prev(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError>;
    /// `expected_generation = None`: the main file must not exist. `Some(g)`: the main file's
    /// generation (per [`peek_generation`]) must be `g`. On success the previous main bytes become
    /// `<name>.prev`. On a precondition failure nothing is written.
    ///
    /// # Errors
    ///
    /// `AlreadyExists`, `Corrupt`, `GenerationConflict`, `TooLarge` or `Io`.
    fn commit(
        &mut self,
        kind: FileKind,
        expected_generation: Option<u64>,
        bytes: &[u8],
    ) -> Result<(), StorageError>;
    /// Renames the main file to `<name>.corrupt-<now_unix>` (never overwrites).
    ///
    /// # Errors
    ///
    /// A [`StorageError`] for I/O failures.
    fn quarantine(&mut self, kind: FileKind, now_unix: u64) -> Result<(), StorageError>;
}

/// The single resident secret buffer (D10), backed by a `VirtualLock` page in yw-app.
///
/// Wipe contract: the [`Vault`] zeroizes the whole slot before it releases it — on
/// [`Vault::lock`], when an operation that received a slot fails, when a new session replaces
/// the old slot, and when the `Vault` itself is dropped (`Drop` locks). Implementations need
/// not wipe on their own drop (the yw-app `LockedBox` does so anyway).
pub trait LockedSlot: Send {
    /// Borrows the slot.
    fn bytes(&self) -> &[u8; SLOT_LEN];
    /// Mutably borrows the slot.
    fn bytes_mut(&mut self) -> &mut [u8; SLOT_LEN];
}

/// Externally visible vault state (spec/02 §6.3, §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultStatus {
    /// No vault and no `.prev`: create or import.
    NoVault,
    /// A structurally valid vault exists; no secrets in memory.
    Locked,
    /// Unlocked DEK; the BIP39 passphrase must be entered.
    PassphraseRequired,
    /// The entered passphrase does not match the stored check value.
    PassphraseMismatch,
    /// Created wallet whose backup is not confirmed: no signing.
    BackupPending,
    /// Fully unlocked; `alt_passphrase` when continuing with a mismatched passphrase.
    Unlocked {
        /// The session uses a passphrase that failed the check value.
        alt_passphrase: bool,
    },
    /// The main vault is damaged (structure, or payload authentication at unlock).
    Corrupt {
        /// Whether `vault.ywv.prev` exists.
        prev_available: bool,
    },
    /// The main vault is missing but `.prev` exists.
    MainMissing,
}

/// Identifier of a payload record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordId([u8; 16]);

impl RecordId {
    /// Wraps raw bytes (meta `record_id`).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Source of an EVM signing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvmKeySource {
    /// `m/44'/60'/0'/0/i` from the mnemonic.
    Derived(crate::bip32::path::AccountIndex),
    /// An imported raw private key.
    Raw(RecordId),
    /// EVM account `i` (`m/44'/60'/0'/0/i`) held on one or more `YubiKey`s (vault tag 5,
    /// spec/10): the PC has no secret for it. [`Vault::evm_address`] answers from the slot map;
    /// every vault signing path refuses it (`RecordNotFound`) — it is signed only through
    /// `evm::sign::*_card`.
    Hardware(crate::bip32::path::AccountIndex),
}

/// A secp256k1 signing key reference for the chain modules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRef {
    /// An EVM key.
    Evm(EvmKeySource),
    /// A derived Bitcoin key `m/{purpose}'/{coin}'/{account}'/{chain}/{index}` (the account node
    /// is `coin`, spec/08 §3.1). Imported Bitcoin keys (vault tag 4) are not lent through
    /// `KeyRef`: the Bitcoin signer gets them from `btc::sign::BtcImportedKeys` together with the
    /// record's network, address type and compression (spec/02 §8.4, spec/08 §11.1).
    Btc {
        /// Account node (purpose, coin type, account).
        coin: crate::bip32::path::BtcCoin,
        /// Receive or change chain.
        chain: crate::bip32::path::BtcChain,
        /// Non-hardened index.
        index: u32,
    },
}

/// Identifier of the current backup challenge.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChallengeId([u8; 16]);

impl fmt::Debug for ChallengeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChallengeId(..)")
    }
}

/// Four 1-based word positions, ascending and distinct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackupChallenge {
    /// Challenge identifier for `confirm_backup`.
    pub id: ChallengeId,
    /// Word positions (1-based, ascending).
    pub positions: [u8; 4],
}

#[cfg(test)]
pub(crate) mod tests;
