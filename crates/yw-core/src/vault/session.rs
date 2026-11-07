//! The `Vault` lock state machine (spec/02 §6.3, §7, §8, §9, §10.3).
//!
//! Resident secrets live only in the caller's [`LockedSlot`] (DEK and, when used, the BIP39
//! passphrase). Every secret operation decrypts the payload from the held ciphertext, derives
//! only what it needs, and wipes it afterwards (§7.3). Backup confirmation ports the aggregated
//! constant-time comparison of `archive/spec-v2.4:crates/secret-core/src/vault.rs:933-994` and
//! the position choice of `archive/spec-v2.4:crates/key-agent/src/vault_session.rs:681-746`.

use core::cell::Cell;
use core::fmt;

use secp256k1::{All, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::format::{
    self, Bip39Record, BtcKeyRecord, HwKeyEntry, MAX_RAW_KEYS, Payload, RawKeyRecord, SealMaterial,
    SolKeyRecord,
};
use super::{
    BackupChallenge, ChallengeId, EvmKeySource, FileKind, KDF_V3, KdfParams, KeyRef, LockedSlot,
    MAX_MNEMONICS, RecordId, SLOT_LEN, VaultStatus, VaultStorage,
};
use crate::bip32::path::{AccountIndex, BtcChain, BtcCoin, btc_path, evm_path};
use crate::bip32::{
    AccountXpub, btc_account_xpub_from_seed, evm_address_from_seed, secret_key_from_seed,
};
use crate::bip39::Mnemonic;
use crate::entropy::{
    OsRandom, RandomSource, random_array_with, random_nonzero_id_with, random_secret32_with,
    secp_context,
};
use crate::error::{KeyError, StorageError, VaultError};
use crate::evm::Address;
use crate::hex;
use crate::keyimport::{
    BtcKeyInfo, ImportChain, ImportInner, ImportKey, btc_info, parse_evm_private_key,
};
use crate::password::{Bip39Passphrase, VaultPassword};
use crate::secret::{SecretBytes, SecretString, SecretVec};
use crate::slip10::SolKeySource;
use crate::yubikey::record::{HwKeyRecord, records_consistent};

const MAX_ADDRESS_BATCH: usize = 100;
/// `sol_public_keys` batch bound (spec/02 §10.3).
const MAX_SOL_KEY_BATCH: usize = 128;
const CHALLENGE_WORDS: usize = 4;
const SLOT_DEK_END: usize = 32;
const SLOT_FLAG: usize = 32;
const SLOT_PASSPHRASE_LEN: usize = 33;
/// The other mnemonics' passphrase entries (`SLOT_LEN` doc): `[0]` present, `[1..17)` record
/// id, then the same length + bytes field as the primary passphrase.
const SLOT_EXTRA: usize = 320;
const SLOT_EXTRA_LEN: usize = 275;
const SLOT_EXTRA_FIELD: usize = 17;
/// Length + bytes of one passphrase field (u16 BE length, up to 256 bytes).
const SLOT_FIELD_LEN: usize = 258;
const INTERNAL: VaultError = VaultError::Key(KeyError::Internal);

type Slot = Box<dyn LockedSlot>;

/// A sidecar's generation plus its plaintext (redacting [`SecretVec`]).
pub type SidecarContents = (u64, SecretVec);

/// Public facts of every imported key, in payload order, and whether the vault has recovery
/// words (spec/02 §10.3 `imported_keys`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedKeys {
    /// `false` for a key-only vault (no `Bip39` record).
    pub has_mnemonic: bool,
    /// EVM keys (`tag 2`) and their addresses.
    pub evm: Vec<(RecordId, Address)>,
    /// Solana keys (`tag 3`) and their public keys.
    pub sol: Vec<(RecordId, [u8; 32])>,
    /// Bitcoin keys (`tag 4`) and their facts.
    pub btc: Vec<(RecordId, BtcKeyInfo)>,
    /// Zcash transparent keys (`tag 6`) and their facts.
    pub zec: Vec<(RecordId, crate::keyimport::ZecKeyInfo)>,
}

/// A password change that took effect (spec/02 §4.4): the `Rewrap` commit landed, so the new
/// password is the one that opens `vault.ywv` from now on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordChange {
    /// The follow-up `PayloadRewrite` also landed: `vault.ywv.prev` uses the new password too.
    Complete,
    /// The follow-up `PayloadRewrite` failed: the new password is in effect, but
    /// `vault.ywv.prev` may still open only with the OLD password (a later save refreshes it).
    PrevNotRefreshed,
}

/// One recovery phrase of the vault (`Bip39` record, spec/02 §4.6): public facts only. The label
/// is meta's (yw-app); the record id is the stable mnemonic id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MnemonicInfo {
    /// Record id (the mnemonic id accounts refer to).
    pub id: RecordId,
    /// Creation or import time (Unix seconds, from yw-app).
    pub created_unix: u64,
    /// 12, 15, 18, 21 or 24.
    pub words: usize,
    /// A BIP39 passphrase is used with it.
    pub passphrase_used: bool,
    /// The backup quiz is done (imported phrases count as confirmed).
    pub backup_confirmed: bool,
    /// The first record: the accounts of the existing meta keys (`evm_accounts`, …) and of
    /// `EvmKeySource::Derived` come from it; it cannot be removed.
    pub primary: bool,
}

/// Which mnemonic the passphrase screen asks for (`PassphraseRequired`/`PassphraseMismatch`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingPassphrase {
    /// The record asked for.
    pub id: RecordId,
    /// 1-based position among the vault's mnemonics (the label is in meta, still closed).
    pub position: usize,
    /// Number of mnemonics in the vault.
    pub count: usize,
}

/// An opened vault file: its bytes, `vault_id`, the unwrapped DEK, the status it unlocks to and
/// the first mnemonic whose passphrase is asked for.
type Opened = (
    Vec<u8>,
    [u8; 16],
    Zeroizing<[u8; 32]>,
    VaultStatus,
    Option<[u8; 16]>,
);

/// What the vault knows about a sidecar file's generation (for the commit CAS).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Known {
    /// Not read or written in this session: `save_sidecar` authenticates the file first.
    Unknown,
    /// The file did not exist.
    Absent,
    /// The last generation read or written.
    Generation(u64),
    /// The last open failed authentication or structure (`SidecarCorrupt`,
    /// `SidecarVaultMismatch`): saving is refused until a later open succeeds, so a file that
    /// may still be restored (spec/02 §6.3, E-VLT-006) is never overwritten.
    Failed(VaultError),
}

impl Known {
    const fn from_option(generation: Option<u64>) -> Self {
        match generation {
            Some(generation) => Self::Generation(generation),
            None => Self::Absent,
        }
    }
}

/// The wallet vault. `Send` but not `Sync`: yw-app drives it from one key-worker thread.
pub struct Vault {
    storage: Box<dyn VaultStorage>,
    status: VaultStatus,
    id: Option<[u8; 16]>,
    /// Current `vault.ywv` bytes (ciphertext) while a session is open.
    ciphertext: Option<Vec<u8>>,
    slot: Option<Slot>,
    /// The open backup quiz: id, word positions and the mnemonic it checks.
    challenge: Option<(ChallengeId, [u8; CHALLENGE_WORDS], [u8; 16])>,

    /// Last known generation of meta / journal.
    sidecar_generations: Cell<[Known; 2]>,
    kdf: KdfParams,
    /// `now_unix` of the last `.prev` recovery that moved `vault.ywv` aside
    /// (`vault.ywv.corrupt-<now_unix>`).
    quarantined_at: Option<u64>,
    /// The mnemonic whose passphrase `PassphraseRequired`/`PassphraseMismatch` asks for.
    passphrase_target: Option<[u8; 16]>,
    /// A mismatched passphrase was accepted for some mnemonic in this session.
    alt_passphrase: bool,
}

impl fmt::Debug for Vault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Vault")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

fn wipe_and_drop(mut slot: Slot) {
    slot.bytes_mut().zeroize();
    drop(slot);
}

/// `commit`, and when the storage reports a failure, a re-read of the main file: bytes equal
/// to the ones written mean the commit landed (e.g. the spec/02 §6.2 step 6 read-back failed
/// after the replace) and count as success, so the in-memory state follows the disk. Each
/// written file carries a fresh random nonce, so equal bytes can only come from this commit.
fn commit_landed(
    storage: &mut dyn VaultStorage,
    kind: FileKind,
    expected: Option<u64>,
    bytes: &[u8],
) -> Result<(), StorageError> {
    let Err(error) = storage.commit(kind, expected, bytes) else {
        return Ok(());
    };
    match storage.load(kind) {
        Ok(Some(current)) if current == bytes => Ok(()),
        _ => Err(error),
    }
}

fn slot_dek(slot: Option<&Slot>) -> Result<&[u8; 32], VaultError> {
    slot.ok_or(VaultError::InvalidState)?
        .bytes()
        .first_chunk::<SLOT_DEK_END>()
        .ok_or(INTERNAL)
}

/// The passphrase in the field at `at` (u16 BE length, then the bytes).
fn read_field(bytes: &[u8; SLOT_LEN], at: usize) -> Result<Bip39Passphrase, VaultError> {
    let start = at.checked_add(2).ok_or(INTERNAL)?;
    let len_bytes = bytes.get(at..start).ok_or(INTERNAL)?;
    let len = usize::from(u16::from_be_bytes(
        len_bytes.try_into().map_err(|_| INTERNAL)?,
    ));
    let end = start
        .checked_add(len)
        .filter(|end| *end <= at.saturating_add(SLOT_FIELD_LEN))
        .ok_or(INTERNAL)?;
    Ok(Bip39Passphrase::from_bytes(
        bytes.get(start..end).ok_or(INTERNAL)?,
    )?)
}

/// Writes `passphrase` into the (already zeroed) field at `at`.
fn write_field(
    bytes: &mut [u8; SLOT_LEN],
    at: usize,
    passphrase: &Bip39Passphrase,
) -> Result<(), VaultError> {
    let value = passphrase.as_bytes();
    let len = u16::try_from(value.len()).map_err(|_| INTERNAL)?;
    let start = at.checked_add(2).ok_or(INTERNAL)?;
    let end = start
        .checked_add(value.len())
        .filter(|end| *end <= at.saturating_add(SLOT_FIELD_LEN))
        .ok_or(INTERNAL)?;
    bytes
        .get_mut(at..start)
        .ok_or(INTERNAL)?
        .copy_from_slice(&len.to_be_bytes());
    bytes
        .get_mut(start..end)
        .ok_or(INTERNAL)?
        .copy_from_slice(value);
    Ok(())
}

/// Start offsets of the other mnemonics' passphrase entries.
fn extra_entries() -> impl Iterator<Item = usize> {
    (0..MAX_MNEMONICS.saturating_sub(1))
        .map(|entry| SLOT_EXTRA.saturating_add(entry.saturating_mul(SLOT_EXTRA_LEN)))
}

/// The entry holding the passphrase of the non-primary record `id`.
fn find_extra(bytes: &[u8; SLOT_LEN], id: &[u8; 16]) -> Option<usize> {
    extra_entries().find(|base| {
        bytes.get(*base).copied() == Some(1)
            && bytes.get(base.saturating_add(1)..base.saturating_add(SLOT_EXTRA_FIELD))
                == Some(id.as_slice())
    })
}

/// The passphrase stored for record `id` (`primary`: the first record's area), `None` when none
/// was entered.
fn stored_passphrase(
    bytes: &[u8; SLOT_LEN],
    id: &[u8; 16],
    primary: bool,
) -> Result<Option<Bip39Passphrase>, VaultError> {
    if primary {
        if bytes.get(SLOT_FLAG).copied() != Some(1) {
            return Ok(None);
        }
        return read_field(bytes, SLOT_PASSPHRASE_LEN).map(Some);
    }
    find_extra(bytes, id)
        .map(|base| read_field(bytes, base.saturating_add(SLOT_EXTRA_FIELD)))
        .transpose()
}

/// Clears the primary passphrase area and, if given, stores the passphrase.
fn set_slot_passphrase(
    slot: &mut dyn LockedSlot,
    passphrase: Option<&Bip39Passphrase>,
) -> Result<(), VaultError> {
    let bytes = slot.bytes_mut();
    bytes
        .get_mut(SLOT_FLAG..SLOT_EXTRA)
        .ok_or(INTERNAL)?
        .zeroize();
    if let Some(passphrase) = passphrase {
        *bytes.get_mut(SLOT_FLAG).ok_or(INTERNAL)? = 1;
        write_field(bytes, SLOT_PASSPHRASE_LEN, passphrase)?;
    }
    Ok(())
}

/// Stores (`Some`) or clears (`None`) the passphrase of record `id` (`primary`: the first
/// record).
fn set_record_passphrase(
    slot: &mut dyn LockedSlot,
    id: &[u8; 16],
    primary: bool,
    passphrase: Option<&Bip39Passphrase>,
) -> Result<(), VaultError> {
    if primary {
        return set_slot_passphrase(slot, passphrase);
    }
    let bytes = slot.bytes_mut();
    if let Some(base) = find_extra(bytes, id) {
        bytes
            .get_mut(base..base.saturating_add(SLOT_EXTRA_LEN))
            .ok_or(INTERNAL)?
            .zeroize();
    }
    let Some(passphrase) = passphrase else {
        return Ok(());
    };
    let base = extra_entries()
        .find(|base| bytes.get(*base).copied() != Some(1))
        .ok_or(INTERNAL)?;
    *bytes.get_mut(base).ok_or(INTERNAL)? = 1;
    bytes
        .get_mut(base.saturating_add(1)..base.saturating_add(SLOT_EXTRA_FIELD))
        .ok_or(INTERNAL)?
        .copy_from_slice(id);
    write_field(bytes, base.saturating_add(SLOT_EXTRA_FIELD), passphrase)
}

fn fill_slot(
    slot: &mut dyn LockedSlot,
    dek: &[u8; 32],
    passphrase: Option<&Bip39Passphrase>,
) -> Result<(), VaultError> {
    slot.bytes_mut().zeroize();
    slot.bytes_mut()
        .get_mut(..SLOT_DEK_END)
        .ok_or(INTERNAL)?
        .copy_from_slice(dek);
    set_slot_passphrase(slot, passphrase)
}

/// The state once every passphrase is in: `BackupPending` while the primary mnemonic's quiz is
/// open (a created wallet), else unlocked. A key-only vault has neither step.
fn status_when_ready(payload: &Payload, alt_passphrase: bool) -> VaultStatus {
    match payload.primary() {
        Some(record) if !record.backup_confirmed => VaultStatus::BackupPending,
        _ => VaultStatus::Unlocked { alt_passphrase },
    }
}

/// The state after opening a payload and the mnemonic asked for first: every mnemonic with a
/// BIP39 passphrase asks for it in payload order (spec/02 §7.5).
fn status_after_unlock(payload: &Payload) -> (VaultStatus, Option<[u8; 16]>) {
    match payload.bip39.iter().find(|record| record.passphrase_used) {
        Some(record) => (VaultStatus::PassphraseRequired, Some(record.record_id)),
        None => (status_when_ready(payload, false), None),
    }
}

/// The primary BIP39 record, or `NoMnemonic` for a vault without recovery words.
fn mnemonic_record(payload: &Payload) -> Result<&Bip39Record, VaultError> {
    payload.primary().ok_or(VaultError::NoMnemonic)
}

/// The BIP39 record `id` and whether it is the primary one (`RecordNotFound`).
fn record_of<'a>(
    payload: &'a Payload,
    id: &[u8; 16],
) -> Result<(&'a Bip39Record, bool), VaultError> {
    let record = payload.mnemonic(id).ok_or(VaultError::RecordNotFound)?;
    let primary = payload
        .primary()
        .is_some_and(|first| first.record_id == *id);
    Ok((record, primary))
}

const fn sidecar_index(kind: FileKind) -> Result<usize, VaultError> {
    match kind {
        FileKind::Meta => Ok(0),
        FileKind::Journal => Ok(1),
        FileKind::Vault => Err(VaultError::InvalidState),
    }
}

/// `SHA-256(addr0)[0..4]` for the passphrase typo check (spec/02 §4.6).
fn passphrase_check(address: &Address) -> [u8; 4] {
    let digest = Sha256::digest(address.as_bytes());
    let mut out = [0_u8; 4];
    for (slot, byte) in out.iter_mut().zip(digest.iter()) {
        *slot = *byte;
    }
    out
}

/// Address of account 0 under `passphrase`.
fn address_zero(
    ctx: &Secp256k1<All>,
    mnemonic: &Mnemonic,
    passphrase: &Bip39Passphrase,
) -> Result<Address, VaultError> {
    let seed = mnemonic.to_seed(passphrase)?;
    Ok(evm_address_from_seed(
        ctx,
        seed.expose(),
        AccountIndex::ZERO,
    )?)
}

fn fresh_record_id(rng: &mut impl RandomSource, payload: &Payload) -> Result<[u8; 16], VaultError> {
    let id = random_nonzero_id_with(rng)?;
    if payload.has_id(&id) {
        return Err(KeyError::RandomnessUnavailable.into());
    }
    Ok(id)
}

/// Adds a parsed key to `payload` (per-chain cap 15, duplicates refused).
fn add_key(
    payload: &mut Payload,
    key: ImportKey,
    record_id: [u8; 16],
    now_unix: u64,
) -> Result<(), VaultError> {
    match key.inner {
        ImportInner::Evm(secret) => {
            let duplicate = payload.raw_keys.iter().fold(0_u8, |seen, raw| {
                seen | raw.key.as_slice().ct_eq(secret.as_slice()).unwrap_u8()
            });
            if duplicate != 0 {
                return Err(VaultError::DuplicateKey);
            }
            if payload.raw_keys.len() >= MAX_RAW_KEYS {
                return Err(VaultError::RecordLimit);
            }
            payload.raw_keys.push(RawKeyRecord {
                record_id,
                created_unix: now_unix,
                key: secret,
            });
        }
        ImportInner::Sol { seed, public } => {
            if payload.sol_keys.iter().any(|sol| sol.public == public) {
                return Err(VaultError::DuplicateKey);
            }
            if payload.sol_keys.len() >= MAX_RAW_KEYS {
                return Err(VaultError::RecordLimit);
            }
            payload.sol_keys.push(SolKeyRecord {
                record_id,
                created_unix: now_unix,
                seed,
                public,
            });
        }
        ImportInner::Btc {
            secret,
            compressed,
            network,
            script,
        } => {
            let duplicate = payload.btc_keys.iter().fold(0_u8, |seen, btc| {
                let same_secret = btc.secret.as_slice().ct_eq(secret.as_slice()).unwrap_u8();
                let same_use = u8::from(
                    btc.compressed == compressed && btc.network == network && btc.script == script,
                );
                seen | (same_secret & same_use)
            });
            if duplicate != 0 {
                return Err(VaultError::DuplicateKey);
            }
            if payload.btc_keys.len() >= MAX_RAW_KEYS {
                return Err(VaultError::RecordLimit);
            }
            payload.btc_keys.push(BtcKeyRecord {
                record_id,
                created_unix: now_unix,
                secret,
                compressed,
                network,
                script,
            });
        }
        ImportInner::Zec { secret, network } => {
            let duplicate = payload
                .zec_keys
                .iter()
                .fold(0_u8, |seen, zec| seen | zec.same_as(&secret, network));
            if duplicate != 0 {
                return Err(VaultError::DuplicateKey);
            }
            if payload.zec_keys.len() >= MAX_RAW_KEYS {
                return Err(VaultError::RecordLimit);
            }
            payload.zec_keys.push(format::ZecKeyRecord {
                record_id,
                created_unix: now_unix,
                secret,
                network,
            });
        }
    }
    Ok(())
}

/// Removes the imported record `id` (any chain); `None` when no imported record has that id.
fn remove_key(payload: &mut Payload, id: &[u8; 16]) -> Option<ImportChain> {
    let before = (
        payload.raw_keys.len(),
        payload.sol_keys.len(),
        payload.btc_keys.len(),
        payload.zec_keys.len(),
    );
    payload.raw_keys.retain(|raw| raw.record_id != *id);
    payload.sol_keys.retain(|sol| sol.record_id != *id);
    payload.btc_keys.retain(|btc| btc.record_id != *id);
    payload.zec_keys.retain(|zec| zec.record_id != *id);
    if payload.raw_keys.len() != before.0 {
        Some(ImportChain::Evm)
    } else if payload.sol_keys.len() != before.1 {
        Some(ImportChain::Sol)
    } else if payload.btc_keys.len() != before.2 {
        Some(ImportChain::Btc)
    } else if payload.zec_keys.len() != before.3 {
        Some(ImportChain::Zec)
    } else {
        None
    }
}

impl Vault {
    /// Classifies the files on disk (spec/02 §6.3). Orphan `.tmp` files are removed by the
    /// storage implementation when it is created.
    ///
    /// # Errors
    ///
    /// [`VaultError::Storage`] when the storage cannot be read.
    pub fn load(storage: Box<dyn VaultStorage>) -> Result<Self, VaultError> {
        Self::load_with_params(storage, KDF_V3)
    }

    pub(crate) fn load_with_params(
        storage: Box<dyn VaultStorage>,
        kdf: KdfParams,
    ) -> Result<Self, VaultError> {
        let main = storage.load(FileKind::Vault).map_err(VaultError::Storage)?;
        let prev_available = || {
            storage
                .load_prev(FileKind::Vault)
                .map(|prev| prev.is_some())
                .map_err(VaultError::Storage)
        };
        let (status, vault_id) = match main {
            Some(bytes) => match format::decode_header(&bytes, &kdf) {
                Ok(header) => (VaultStatus::Locked, Some(header.vault_id)),
                Err(_) => (
                    VaultStatus::Corrupt {
                        prev_available: prev_available()?,
                    },
                    None,
                ),
            },
            None if prev_available()? => (VaultStatus::MainMissing, None),
            None => (VaultStatus::NoVault, None),
        };
        Ok(Self {
            storage,
            status,
            id: vault_id,
            ciphertext: None,
            slot: None,
            challenge: None,
            sidecar_generations: Cell::new([Known::Unknown; 2]),
            kdf,
            quarantined_at: None,
            passphrase_target: None,
            alt_passphrase: false,
        })
    }

    /// The current state.
    #[must_use]
    pub const fn status(&self) -> VaultStatus {
        self.status
    }

    /// `now_unix` of the last `.prev` recovery in this process that moved the main file aside
    /// as `vault.ywv.corrupt-<now_unix>` (shown so the user can restore it by hand).
    #[must_use]
    pub const fn quarantined_at(&self) -> Option<u64> {
        self.quarantined_at
    }

    /// The vault identifier once known (after load, create, import or recovery).
    #[must_use]
    pub const fn vault_id(&self) -> Option<[u8; 16]> {
        self.id
    }

    fn require_public(&self) -> Result<(), VaultError> {
        match self.status {
            VaultStatus::BackupPending | VaultStatus::Unlocked { .. } => Ok(()),
            _ => Err(VaultError::InvalidState),
        }
    }

    fn require_signing(&self) -> Result<(), VaultError> {
        match self.status {
            VaultStatus::Unlocked { .. } => Ok(()),
            VaultStatus::BackupPending => Err(VaultError::BackupNotConfirmed),
            _ => Err(VaultError::InvalidState),
        }
    }

    fn current_bytes(&self) -> Result<&[u8], VaultError> {
        self.ciphertext.as_deref().ok_or(VaultError::InvalidState)
    }

    pub(super) fn payload(&self) -> Result<Payload, VaultError> {
        format::decrypt_payload(
            self.current_bytes()?,
            slot_dek(self.slot.as_ref())?,
            &self.kdf,
        )
    }

    /// The BIP39 seed of the primary mnemonic (`NoMnemonic` without one).
    fn seed(&self, payload: &Payload) -> Result<SecretBytes<64>, VaultError> {
        let id = mnemonic_record(payload)?.record_id;
        self.seed_of(payload, &id)
    }

    /// The BIP39 seed of mnemonic `id` with its passphrase from the slot. A mnemonic that uses a
    /// passphrase not entered yet is `InvalidState` (never the empty-passphrase wallet).
    fn seed_of(&self, payload: &Payload, id: &[u8; 16]) -> Result<SecretBytes<64>, VaultError> {
        let (record, primary) = record_of(payload, id)?;
        let bytes = self.slot.as_ref().ok_or(VaultError::InvalidState)?.bytes();
        let passphrase = match stored_passphrase(bytes, id, primary)? {
            Some(passphrase) => passphrase,
            None if record.passphrase_used => return Err(VaultError::InvalidState),
            None => Bip39Passphrase::empty(),
        };
        Ok(record.mnemonic.to_seed(&passphrase)?)
    }

    /// Signing with a key of a mnemonic whose backup quiz is open is refused. The wallet-level
    /// `BackupPending` covers a created wallet's primary mnemonic at unlock; this also covers a
    /// mnemonic made later ("새 복구 단어 만들기", which in a key-only vault becomes the primary
    /// one).
    fn require_key_backup(payload: &Payload, key: KeyRef) -> Result<(), VaultError> {
        let record = match key {
            KeyRef::Evm(EvmKeySource::Mnemonic(id, _))
            | KeyRef::Btc {
                mnemonic: Some(id), ..
            }
            | KeyRef::Zec {
                mnemonic: Some(id), ..
            } => payload.mnemonic(id.as_bytes()),
            KeyRef::Evm(EvmKeySource::Raw(_) | EvmKeySource::Hardware(_))
            | KeyRef::ZecImported { .. } => None,
            KeyRef::Evm(EvmKeySource::Derived(_))
            | KeyRef::Btc { mnemonic: None, .. }
            | KeyRef::Zec { mnemonic: None, .. } => payload.primary(),
        };
        if record.is_some_and(|record| !record.backup_confirmed) {
            return Err(VaultError::BackupNotConfirmed);
        }
        Ok(())
    }

    fn secret_for(
        &self,
        ctx: &Secp256k1<All>,
        payload: &Payload,
        key: KeyRef,
    ) -> Result<SecretKey, VaultError> {
        let mut mnemonic = None;
        let path = match key {
            KeyRef::Evm(EvmKeySource::Raw(id)) => {
                let raw = payload
                    .raw_keys
                    .iter()
                    .find(|raw| raw.record_id == *id.as_bytes())
                    .ok_or(VaultError::RecordNotFound)?;
                return SecretKey::from_byte_array(*raw.key).map_err(|_| INTERNAL);
            }
            KeyRef::Evm(EvmKeySource::Derived(index)) => evm_path(index),
            KeyRef::Evm(EvmKeySource::Mnemonic(id, index)) => {
                let seed = self.seed_of(payload, id.as_bytes())?;
                return Ok(secret_key_from_seed(ctx, seed.expose(), &evm_path(index))?);
            }
            // A YubiKey account has no key on the PC (spec/10 §1).
            KeyRef::Evm(EvmKeySource::Hardware(_)) => return Err(VaultError::RecordNotFound),
            KeyRef::Btc {
                mnemonic: id,
                coin,
                chain,
                index,
            } => {
                mnemonic = id;
                btc_path(coin, chain, index)?
            }
            KeyRef::Zec {
                mnemonic: id,
                test,
                account,
                index,
            } => {
                mnemonic = id;
                crate::bip32::path::zec_path(test, account, index)?
            }
            KeyRef::ZecImported { network, pubkey } => {
                for record in payload.zec_keys.iter().filter(|zec| zec.network == network) {
                    let mut secret =
                        SecretKey::from_byte_array(*record.secret).map_err(|_| INTERNAL)?;
                    if PublicKey::from_secret_key(ctx, &secret).serialize() == pubkey {
                        return Ok(secret);
                    }
                    secret.non_secure_erase();
                }
                return Err(VaultError::RecordNotFound);
            }
        };
        let seed = self.seed_for(payload, mnemonic)?;
        Ok(secret_key_from_seed(ctx, seed.expose(), &path)?)
    }

    /// The BIP39 seed of mnemonic `id`, or of the primary one for `None` (spec/02 §8.6).
    fn seed_for(
        &self,
        payload: &Payload,
        id: Option<RecordId>,
    ) -> Result<SecretBytes<64>, VaultError> {
        match id {
            Some(id) => self.seed_of(payload, id.as_bytes()),
            None => self.seed(payload),
        }
    }

    fn commit_vault(&mut self, expected: Option<u64>, bytes: Vec<u8>) -> Result<(), VaultError> {
        commit_landed(self.storage.as_mut(), FileKind::Vault, expected, &bytes)
            .map_err(VaultError::Storage)?;
        self.ciphertext = Some(bytes);
        Ok(())
    }

    /// The main `vault.ywv` bytes (`Storage(NotFound)` when absent).
    fn load_main(&self) -> Result<Vec<u8>, VaultError> {
        self.storage
            .load(FileKind::Vault)
            .map_err(VaultError::Storage)?
            .ok_or(VaultError::Storage(StorageError::NotFound))
    }

    /// spec/02 §4.5 steps 1–9 on `bytes`: KEK, DEK unwrap and payload authentication.
    fn open_bytes(&self, bytes: Vec<u8>, password: &VaultPassword) -> Result<Opened, VaultError> {
        let (header, dek) = format::unwrap_dek(&bytes, password, &self.kdf)?;
        let payload = format::decrypt_payload(&bytes, &dek, &self.kdf)?;
        let (next, target) = status_after_unlock(&payload);
        Ok((bytes, header.vault_id, dek, next, target))
    }

    /// Opens the session on an opened file.
    fn finish_open(&mut self, slot: Slot, opened: Opened) -> Result<VaultStatus, VaultError> {
        let (bytes, vault_id, dek, next, target) = opened;
        self.open_session(slot, &dek, None)?;
        self.ciphertext = Some(bytes);
        self.id = Some(vault_id);
        self.status = next;
        self.passphrase_target = target;
        Ok(next)
    }

    /// `PayloadRewrite` (spec/02 §4.4): no KDF, key section unchanged, `generation + 1`.
    fn rewrite_payload(&mut self, payload: &Payload) -> Result<(), VaultError> {
        let current = self.current_bytes()?;
        let generation = format::decode_header(current, &self.kdf)?.generation;
        let nonce = random_array_with::<24>(&mut OsRandom)?;
        let bytes = format::seal_payload_rewrite(
            current,
            slot_dek(self.slot.as_ref())?,
            payload,
            nonce,
            &self.kdf,
        )?;
        self.commit_vault(Some(generation), bytes)
    }

    /// Re-derives the KEK from `password` and compares the unwrapped DEK with the slot (§9).
    fn verify_password(&self, password: &VaultPassword) -> Result<(), VaultError> {
        let (_, dek) = format::unwrap_dek(self.current_bytes()?, password, &self.kdf)?;
        let same = dek
            .as_slice()
            .ct_eq(slot_dek(self.slot.as_ref())?.as_slice());
        if same.unwrap_u8() != 1 {
            return Err(VaultError::UnlockFailed);
        }
        Ok(())
    }

    fn open_session(
        &mut self,
        slot: Slot,
        dek: &[u8; 32],
        passphrase: Option<&Bip39Passphrase>,
    ) -> Result<(), VaultError> {
        let mut slot = slot;
        if let Err(error) = fill_slot(slot.as_mut(), dek, passphrase) {
            wipe_and_drop(slot);
            return Err(error);
        }
        if let Some(old) = self.slot.replace(slot) {
            wipe_and_drop(old);
        }
        self.challenge = None;
        self.passphrase_target = None;
        self.alt_passphrase = false;
        self.sidecar_generations.set([Known::Unknown; 2]);
        Ok(())
    }

    /// Creates a new 24-word wallet (spec/02 §8.1) and returns the phrase for the first display.
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `NoVault`, `RandomnessUnavailable`, `OutOfMemory` or `Storage`.
    /// On failure the state stays `NoVault` and the slot is wiped.
    pub fn create_wallet(
        &mut self,
        password: &VaultPassword,
        slot: Slot,
        now_unix: u64,
    ) -> Result<SecretString, VaultError> {
        self.create_wallet_with_rng(&mut OsRandom, password, slot, now_unix)
    }

    pub(crate) fn create_wallet_with_rng(
        &mut self,
        rng: &mut impl RandomSource,
        password: &VaultPassword,
        slot: Slot,
        now_unix: u64,
    ) -> Result<SecretString, VaultError> {
        if self.status != VaultStatus::NoVault {
            wipe_and_drop(slot);
            return Err(VaultError::InvalidState);
        }
        let sealed = (|| -> Result<_, VaultError> {
            let mnemonic = Mnemonic::generate_with_rng(rng)?;
            let dek = random_secret32_with(rng)?;
            let vault_id = random_nonzero_id_with(rng)?;
            let record_id = random_nonzero_id_with(rng)?;
            let kdf_salt = random_array_with::<16>(rng)?;
            let wrap_nonce = random_array_with::<24>(rng)?;
            let payload_nonce = random_array_with::<24>(rng)?;
            let payload = Payload::new(Some(Bip39Record {
                record_id,
                created_unix: now_unix,
                mnemonic,
                passphrase_used: false,
                backup_confirmed: false,
                passphrase_check: [0; 4],
            }));
            let material = SealMaterial {
                password,
                vault_id,
                dek: &dek,
                kdf_salt,
                wrap_nonce,
                payload_nonce,
                generation: 1,
                payload: &payload,
            };
            let bytes = format::seal_create_with(&material, &self.kdf)?;
            let phrase = mnemonic_record(&payload)?.mnemonic.phrase()?;
            Ok((bytes, dek, vault_id, phrase))
        })();
        let (bytes, dek, vault_id, phrase) = match sealed {
            Ok(values) => values,
            Err(error) => {
                wipe_and_drop(slot);
                return Err(error);
            }
        };
        if let Err(error) = commit_landed(self.storage.as_mut(), FileKind::Vault, None, &bytes) {
            wipe_and_drop(slot);
            return Err(VaultError::Storage(error));
        }
        self.ciphertext = Some(bytes);
        self.id = Some(vault_id);
        self.open_session(slot, &dek, None)?;
        self.status = VaultStatus::BackupPending;
        Ok(phrase)
    }

    /// Imports an existing mnemonic (spec/02 §8.2); backup counts as confirmed.
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `NoVault`, the mnemonic and passphrase `KeyError`s
    /// (`PassphraseEmpty` for `Some` empty), `RandomnessUnavailable`, `OutOfMemory` or `Storage`.
    pub fn import_mnemonic(
        &mut self,
        password: &VaultPassword,
        phrase: &str,
        passphrase: Option<Bip39Passphrase>,
        slot: Slot,
        now_unix: u64,
    ) -> Result<(), VaultError> {
        self.import_mnemonic_with_rng(&mut OsRandom, password, phrase, passphrase, slot, now_unix)
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "spec/02 §10.3: the passphrase moves into the vault and is wiped on return"
    )]
    pub(crate) fn import_mnemonic_with_rng(
        &mut self,
        rng: &mut impl RandomSource,
        password: &VaultPassword,
        phrase: &str,
        passphrase: Option<Bip39Passphrase>,
        slot: Slot,
        now_unix: u64,
    ) -> Result<(), VaultError> {
        if self.status != VaultStatus::NoVault {
            wipe_and_drop(slot);
            return Err(VaultError::InvalidState);
        }
        let sealed = (|| -> Result<_, VaultError> {
            let mnemonic = Mnemonic::parse(phrase)?;
            if passphrase.as_ref().is_some_and(Bip39Passphrase::is_empty) {
                return Err(KeyError::PassphraseEmpty.into());
            }
            let passphrase_check = match &passphrase {
                Some(value) => {
                    passphrase_check(&address_zero(&secp_context(rng)?, &mnemonic, value)?)
                }
                None => [0; 4],
            };
            let dek = random_secret32_with(rng)?;
            let vault_id = random_nonzero_id_with(rng)?;
            let record_id = random_nonzero_id_with(rng)?;
            let kdf_salt = random_array_with::<16>(rng)?;
            let wrap_nonce = random_array_with::<24>(rng)?;
            let payload_nonce = random_array_with::<24>(rng)?;
            let payload = Payload::new(Some(Bip39Record {
                record_id,
                created_unix: now_unix,
                mnemonic,
                passphrase_used: passphrase.is_some(),
                backup_confirmed: true,
                passphrase_check,
            }));
            let material = SealMaterial {
                password,
                vault_id,
                dek: &dek,
                kdf_salt,
                wrap_nonce,
                payload_nonce,
                generation: 1,
                payload: &payload,
            };
            Ok((
                format::seal_create_with(&material, &self.kdf)?,
                dek,
                vault_id,
            ))
        })();
        let (bytes, dek, vault_id) = match sealed {
            Ok(values) => values,
            Err(error) => {
                wipe_and_drop(slot);
                return Err(error);
            }
        };
        if let Err(error) = commit_landed(self.storage.as_mut(), FileKind::Vault, None, &bytes) {
            wipe_and_drop(slot);
            return Err(VaultError::Storage(error));
        }
        self.ciphertext = Some(bytes);
        self.id = Some(vault_id);
        self.open_session(slot, &dek, passphrase.as_ref())?;
        self.status = VaultStatus::Unlocked {
            alt_passphrase: false,
        };
        Ok(())
    }

    /// Unlocks with the password (spec/02 §4.5 steps 1–9, §7.2).
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `Locked`; `Malformed`/`UnsupportedVersion`/`UnsupportedParams`
    /// before any KDF; `UnlockFailed`; `OutOfMemory`; `PayloadCorrupt` (the state becomes
    /// `Corrupt` so `.prev` recovery can be offered); `Storage`.
    pub fn unlock(
        &mut self,
        password: &VaultPassword,
        slot: Slot,
    ) -> Result<VaultStatus, VaultError> {
        if self.status != VaultStatus::Locked {
            wipe_and_drop(slot);
            return Err(VaultError::InvalidState);
        }
        let opened = self
            .load_main()
            .and_then(|bytes| self.open_bytes(bytes, password));
        match opened {
            Ok(opened) => self.finish_open(slot, opened),
            Err(error) => {
                wipe_and_drop(slot);
                if error == VaultError::PayloadCorrupt {
                    let prev_available = self
                        .storage
                        .load_prev(FileKind::Vault)
                        .map_err(VaultError::Storage)?
                        .is_some();
                    self.status = VaultStatus::Corrupt { prev_available };
                }
                Err(error)
            }
        }
    }

    /// Which mnemonic the passphrase screen asks for (`PassphraseRequired`/`PassphraseMismatch`
    /// only; `None` otherwise).
    #[must_use]
    pub fn pending_passphrase(&self) -> Option<PendingPassphrase> {
        if !matches!(
            self.status,
            VaultStatus::PassphraseRequired | VaultStatus::PassphraseMismatch
        ) {
            return None;
        }
        let target = self.passphrase_target?;
        let payload = self.payload().ok()?;
        let position = payload
            .bip39
            .iter()
            .position(|record| record.record_id == target)?;
        Some(PendingPassphrase {
            id: RecordId(target),
            position: position.saturating_add(1),
            count: payload.bip39.len(),
        })
    }

    /// Moves on after the asked passphrase was accepted: the next mnemonic that uses a
    /// passphrase not entered yet, else the final state.
    fn next_passphrase(&mut self) -> Result<VaultStatus, VaultError> {
        let payload = self.payload()?;
        let bytes = self.slot.as_ref().ok_or(VaultError::InvalidState)?.bytes();
        let mut next = None;
        for (position, record) in payload.bip39.iter().enumerate() {
            if record.passphrase_used
                && stored_passphrase(bytes, &record.record_id, position == 0)?.is_none()
            {
                next = Some(record.record_id);
                break;
            }
        }
        self.passphrase_target = next;
        self.status = match next {
            Some(_) => VaultStatus::PassphraseRequired,
            None => status_when_ready(&payload, self.alt_passphrase),
        };
        Ok(self.status)
    }

    /// Checks the BIP39 passphrase of the mnemonic asked for ([`Vault::pending_passphrase`])
    /// against its stored 4-byte value (spec/02 §7.5). With several mnemonics that use a
    /// passphrase, a match moves on to the next one (`PassphraseRequired` again).
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `PassphraseRequired`, `Key(PassphraseEmpty)`, or a derivation error.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "spec/02 §10.3: the passphrase moves into the vault and is wiped on return"
    )]
    pub fn enter_passphrase(
        &mut self,
        passphrase: Bip39Passphrase,
    ) -> Result<VaultStatus, VaultError> {
        if self.status != VaultStatus::PassphraseRequired {
            return Err(VaultError::InvalidState);
        }
        if passphrase.is_empty() {
            return Err(KeyError::PassphraseEmpty.into());
        }
        let target = self.passphrase_target.ok_or(VaultError::InvalidState)?;
        let payload = self.payload()?;
        let (bip39, primary) = record_of(&payload, &target)?;
        let ctx = secp_context(&mut OsRandom)?;
        let check = passphrase_check(&address_zero(&ctx, &bip39.mnemonic, &passphrase)?);
        let matches = check
            .as_slice()
            .ct_eq(bip39.passphrase_check.as_slice())
            .unwrap_u8()
            == 1;
        drop(payload);
        let slot = self.slot.as_mut().ok_or(VaultError::InvalidState)?;
        set_record_passphrase(slot.as_mut(), &target, primary, Some(&passphrase))?;
        if matches {
            return self.next_passphrase();
        }
        self.status = VaultStatus::PassphraseMismatch;
        Ok(self.status)
    }

    /// Discards the mismatched passphrase and asks again.
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `PassphraseMismatch`.
    pub fn retry_passphrase(&mut self) -> Result<VaultStatus, VaultError> {
        if self.status != VaultStatus::PassphraseMismatch {
            return Err(VaultError::InvalidState);
        }
        let target = self.passphrase_target.ok_or(VaultError::InvalidState)?;
        let primary = record_of(&self.payload()?, &target)?.1;
        let slot = self.slot.as_mut().ok_or(VaultError::InvalidState)?;
        set_record_passphrase(slot.as_mut(), &target, primary, None)?;
        self.status = VaultStatus::PassphraseRequired;
        Ok(self.status)
    }

    /// Continues with the mismatched passphrase (a different, valid wallet).
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `PassphraseMismatch`.
    pub fn accept_mismatched_passphrase(&mut self) -> Result<VaultStatus, VaultError> {
        if self.status != VaultStatus::PassphraseMismatch {
            return Err(VaultError::InvalidState);
        }
        self.alt_passphrase = true;
        self.next_passphrase()
    }

    /// Wipes and releases the slot, drops the challenge and the held vault bytes (spec/02 §7.2).
    /// A no-op outside the session states.
    pub fn lock(&mut self) {
        if let Some(slot) = self.slot.take() {
            wipe_and_drop(slot);
        }
        self.challenge = None;
        self.ciphertext = None;
        self.passphrase_target = None;
        self.alt_passphrase = false;
        self.sidecar_generations.set([Known::Unknown; 2]);
        if matches!(
            self.status,
            VaultStatus::PassphraseRequired
                | VaultStatus::PassphraseMismatch
                | VaultStatus::BackupPending
                | VaultStatus::Unlocked { .. }
        ) {
            self.status = VaultStatus::Locked;
        }
    }

    /// Restores `vault.ywv.prev` (spec/02 §6.3): unlock it, quarantine a damaged main file, and
    /// commit its content as a new generation.
    ///
    /// From `Locked` (an explicit user request: a damaged key section `header[0..130]` looks
    /// like a wrong password, so `unlock` alone can never offer `.prev`) the main file is tried
    /// first with `password`. If it opens, nothing is restored: the session opens on the main
    /// file exactly like [`Vault::unlock`]. Only when it cannot be opened (`UnlockFailed`,
    /// `PayloadCorrupt`, structure, or missing) is `.prev` unlocked with the same password and
    /// restored. A wrong password fails both and leaves every file untouched.
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `Locked`/`Corrupt`/`MainMissing`, `Storage(NotFound)` without
    /// `.prev`, and the unlock errors of the `.prev` file.
    pub fn recover_from_prev(
        &mut self,
        password: &VaultPassword,
        slot: Slot,
        now_unix: u64,
    ) -> Result<VaultStatus, VaultError> {
        let from_locked = match self.status {
            VaultStatus::Corrupt { .. } | VaultStatus::MainMissing => false,
            VaultStatus::Locked => true,
            _ => {
                wipe_and_drop(slot);
                return Err(VaultError::InvalidState);
            }
        };
        if from_locked {
            let main = self
                .load_main()
                .and_then(|bytes| self.open_bytes(bytes, password));
            match main {
                Ok(opened) => return self.finish_open(slot, opened),
                Err(
                    VaultError::UnlockFailed
                    | VaultError::PayloadCorrupt
                    | VaultError::Malformed
                    | VaultError::UnsupportedVersion
                    | VaultError::UnsupportedParams
                    | VaultError::Storage(StorageError::NotFound),
                ) => {}
                Err(error) => {
                    wipe_and_drop(slot);
                    return Err(error);
                }
            }
        }
        let recovered = (|| -> Result<_, VaultError> {
            let prev = self
                .storage
                .load_prev(FileKind::Vault)
                .map_err(VaultError::Storage)?
                .ok_or(VaultError::Storage(StorageError::NotFound))?;
            let (header, dek) = format::unwrap_dek(&prev, password, &self.kdf)?;
            let payload = format::decrypt_payload(&prev, &dek, &self.kdf)?;
            let nonce = random_array_with::<24>(&mut OsRandom)?;
            let bytes = format::seal_payload_rewrite(&prev, &dek, &payload, nonce, &self.kdf)?;
            if self
                .storage
                .load(FileKind::Vault)
                .map_err(VaultError::Storage)?
                .is_some()
            {
                self.storage
                    .quarantine(FileKind::Vault, now_unix)
                    .map_err(VaultError::Storage)?;
                self.quarantined_at = Some(now_unix);
            }
            commit_landed(self.storage.as_mut(), FileKind::Vault, None, &bytes)
                .map_err(VaultError::Storage)?;
            let (next, target) = status_after_unlock(&payload);
            Ok((bytes, header.vault_id, dek, next, target))
        })();
        match recovered {
            Ok(opened) => self.finish_open(slot, opened),
            Err(error) => {
                wipe_and_drop(slot);
                Err(error)
            }
        }
    }

    /// Picks 4 distinct word positions (partial Fisher–Yates over `random_below`). A new
    /// challenge replaces the previous one.
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`, or `RandomnessUnavailable`.
    pub fn backup_challenge(&mut self) -> Result<BackupChallenge, VaultError> {
        self.backup_challenge_with_rng(&mut OsRandom)
    }

    pub(crate) fn backup_challenge_with_rng(
        &mut self,
        rng: &mut impl RandomSource,
    ) -> Result<BackupChallenge, VaultError> {
        if self.status != VaultStatus::BackupPending {
            return Err(VaultError::InvalidState);
        }
        let primary = mnemonic_record(&self.payload()?)?.record_id;
        self.challenge_for(rng, primary)
    }

    /// The backup quiz of mnemonic `id` (an added mnemonic made with "새 복구 단어 만들기"; the
    /// primary one while `BackupPending`). A new challenge replaces the previous one.
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `Unlocked` (or `BackupPending` for the primary mnemonic) or when
    /// the backup is already confirmed, `RecordNotFound`, or `RandomnessUnavailable`.
    pub fn backup_challenge_for(&mut self, id: RecordId) -> Result<BackupChallenge, VaultError> {
        self.require_backup_target(&id.0)?;
        self.challenge_for(&mut OsRandom, id.0)
    }

    /// Whether the quiz of `id` may run now: its backup is open, and the wallet is unlocked (or
    /// waits for the primary mnemonic's quiz, which is `id`).
    fn require_backup_target(&self, id: &[u8; 16]) -> Result<(), VaultError> {
        let payload = self.payload()?;
        let (record, primary) = record_of(&payload, id)?;
        let allowed = match self.status {
            VaultStatus::Unlocked { .. } => true,
            VaultStatus::BackupPending => primary,
            _ => false,
        };
        if !allowed || record.backup_confirmed {
            return Err(VaultError::InvalidState);
        }
        Ok(())
    }

    fn challenge_for(
        &mut self,
        rng: &mut impl RandomSource,
        record: [u8; 16],
    ) -> Result<BackupChallenge, VaultError> {
        let payload = self.payload()?;
        let words = record_of(&payload, &record)?
            .0
            .mnemonic
            .word_count()
            .words();
        // The same draw as a mnemonic held in memory (`Mnemonic::backup_positions`).
        let positions: [u8; CHALLENGE_WORDS] =
            crate::bip39::backup_positions_with(rng, words).map_err(VaultError::Key)?;
        let id = ChallengeId(random_nonzero_id_with(rng)?);
        self.challenge = Some((id, positions, record));
        Ok(BackupChallenge { id, positions })
    }

    /// Verifies the 4 challenged mnemonic words (spec/02 §8.3).
    /// All 4 comparisons run in constant time and are decided once.
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`; `ChallengeStale` for an unknown id; `BackupMismatch`
    /// for wrong or malformed answers (the challenge is discarded); `Storage` if the commit fails.
    pub fn confirm_backup(&mut self, id: ChallengeId, words: [&str; 4]) -> Result<(), VaultError> {
        if self.status != VaultStatus::BackupPending {
            return Err(VaultError::InvalidState);
        }
        let primary = mnemonic_record(&self.payload()?)?.record_id;
        self.confirm_record_backup(primary, id, words)
    }

    /// Verifies the quiz of mnemonic `id` ([`Vault::backup_challenge_for`]); signing with its
    /// accounts is allowed afterwards.
    ///
    /// # Errors
    ///
    /// As [`Vault::confirm_backup`]; `InvalidState` also when `id` is not the challenged
    /// mnemonic's state (see [`Vault::backup_challenge_for`]).
    pub fn confirm_backup_for(
        &mut self,
        record: RecordId,
        id: ChallengeId,
        words: [&str; 4],
    ) -> Result<(), VaultError> {
        self.require_backup_target(&record.0)?;
        self.confirm_record_backup(record.0, id, words)
    }

    fn confirm_record_backup(
        &mut self,
        record: [u8; 16],
        id: ChallengeId,
        words: [&str; 4],
    ) -> Result<(), VaultError> {
        let positions = match self.challenge {
            Some((current, positions, target)) if current == id && target == record => positions,
            _ => return Err(VaultError::ChallengeStale),
        };
        self.challenge = None;
        let mut payload = self.payload()?;
        let bip39 = record_of(&payload, &record)?.0;
        // Well-formedness, then four constant-time comparisons decided once (shared with the
        // in-memory confirmation of a `YubiKey` wallet, spec/10 §7.1-1).
        if !bip39.mnemonic.backup_words_match(positions, words)? {
            return Err(VaultError::BackupMismatch);
        }
        if let Some(bip39) = payload
            .bip39
            .iter_mut()
            .find(|bip39| bip39.record_id == record)
        {
            bip39.backup_confirmed = true;
        }
        self.rewrite_payload(&payload)?;
        if self.status == VaultStatus::BackupPending {
            self.status = VaultStatus::Unlocked {
                alt_passphrase: self.alt_passphrase,
            };
        }
        Ok(())
    }

    /// Imports a raw EVM private key (spec/02 §8.2): `PayloadRewrite`, no password.
    ///
    /// # Errors
    ///
    /// `BackupNotConfirmed`/`InvalidState`, `Key(InvalidPrivateKey)`, `DuplicateKey`,
    /// `RecordLimit`, `RandomnessUnavailable` or `Storage`.
    pub fn import_evm_private_key(
        &mut self,
        hex_key: &str,
        now_unix: u64,
    ) -> Result<RecordId, VaultError> {
        self.require_signing()?;
        let key = ImportKey {
            inner: ImportInner::Evm(parse_evm_private_key(hex_key)?),
        };
        self.import_key(key, now_unix)
    }

    /// Imports a parsed key of any chain (spec/02 §8.4): `PayloadRewrite`, no password. The
    /// per-chain cap is 15; the same key (EVM/Solana) or the same key used the same way
    /// (Bitcoin: secret, compression, network, script type) is refused.
    ///
    /// # Errors
    ///
    /// `BackupNotConfirmed`/`InvalidState`, `DuplicateKey`, `RecordLimit`,
    /// `RandomnessUnavailable` or `Storage`.
    pub fn import_key(&mut self, key: ImportKey, now_unix: u64) -> Result<RecordId, VaultError> {
        self.require_signing()?;
        let mut payload = self.payload()?;
        if let ImportInner::Zec { secret, network } = &key.inner {
            self.check_zec_collision(&payload, secret, *network)?;
        }
        let record_id = fresh_record_id(&mut OsRandom, &payload)?;
        add_key(&mut payload, key, record_id, now_unix)?;
        self.rewrite_payload(&payload)?;
        Ok(RecordId(record_id))
    }

    /// An imported Zcash key must not be a key the wallet already has as a Zcash address
    /// (spec/12 §2.3): a `YubiKey` slot's public key (any role), or the standard derived key
    /// `m/44'/{coin}'/0'/0/0` of its network. `DuplicateKey` when it is.
    fn check_zec_collision(
        &self,
        payload: &Payload,
        secret: &[u8; 32],
        network: crate::zec::ZecNetwork,
    ) -> Result<(), VaultError> {
        let info = crate::keyimport::zec_info(secret, network)?;
        let hardware = payload
            .hw_keys
            .iter()
            .flat_map(|entry| &entry.record.slots)
            .any(|slot| slot.public == crate::yubikey::record::HwPublicKey::Secp256k1(info.pubkey));
        if hardware {
            return Err(VaultError::DuplicateKey);
        }
        // The standard key of every mnemonic (an added one's is a Zcash account too, §8.6).
        let ctx = secp_context(&mut OsRandom)?;
        let test = network == crate::zec::ZecNetwork::Testnet;
        for (position, record) in payload.bip39.iter().enumerate() {
            let mut derived = self.secret_for(
                &ctx,
                payload,
                KeyRef::Zec {
                    mnemonic: (position > 0).then_some(RecordId(record.record_id)),
                    test,
                    account: 0,
                    index: 0,
                },
            )?;
            let same = PublicKey::from_secret_key(&ctx, &derived).serialize() == info.pubkey;
            derived.non_secure_erase();
            if same {
                return Err(VaultError::DuplicateKey);
            }
        }
        Ok(())
    }

    /// Removes an imported EVM key after re-entering the password. The BIP39 record cannot be
    /// removed.
    ///
    /// # Errors
    ///
    /// `BackupNotConfirmed`/`InvalidState`, `UnlockFailed`, `RecordNotFound` (also for a
    /// non-EVM record), `LastKey` or `Storage`.
    pub fn remove_evm_raw_key(
        &mut self,
        password: &VaultPassword,
        id: RecordId,
    ) -> Result<(), VaultError> {
        self.remove_checked(password, id, Some(ImportChain::Evm))
            .map(|_| ())
    }

    /// Removes an imported key of any chain after re-entering the password (spec/02 §8.4). The
    /// BIP39 record cannot be removed, and neither can the last key of a key-only vault.
    ///
    /// # Errors
    ///
    /// `BackupNotConfirmed`/`InvalidState`, `UnlockFailed`, `RecordNotFound`, `LastKey` or
    /// `Storage`.
    pub fn remove_imported_key(
        &mut self,
        password: &VaultPassword,
        id: RecordId,
    ) -> Result<ImportChain, VaultError> {
        self.remove_checked(password, id, None)
    }

    /// Password check, then removal of `id` (restricted to `only` when given).
    fn remove_checked(
        &mut self,
        password: &VaultPassword,
        id: RecordId,
        only: Option<ImportChain>,
    ) -> Result<ImportChain, VaultError> {
        self.require_signing()?;
        self.verify_password(password)?;
        let mut payload = self.payload()?;
        let chain = remove_key(&mut payload, &id.0)
            .filter(|chain| only.is_none_or(|wanted| wanted == *chain))
            .ok_or(VaultError::RecordNotFound)?;
        if payload.record_count() == 0 {
            return Err(VaultError::LastKey);
        }
        self.rewrite_payload(&payload)?;
        Ok(chain)
    }

    /// `Rewrap` with the new password, then one more `PayloadRewrite` so `.prev` also uses the
    /// new password (spec/02 §4.4). The DEK is unchanged.
    ///
    /// Once the `Rewrap` commit has landed the change is in effect and this returns `Ok`: a
    /// failed follow-up rewrite is [`PasswordChange::PrevNotRefreshed`], never an error (the
    /// old password no longer opens `vault.ywv`, so "failed" would be false).
    ///
    /// # Errors
    ///
    /// `InvalidState`, `UnlockFailed` for a wrong old password, `OutOfMemory` or `Storage` —
    /// all with the old password still in effect.
    pub fn change_password(
        &mut self,
        old: &VaultPassword,
        new: &VaultPassword,
    ) -> Result<PasswordChange, VaultError> {
        self.require_public()?;
        self.verify_password(old)?;
        let payload = self.payload()?;
        let current = self.current_bytes()?;
        let header = format::decode_header(current, &self.kdf)?;
        let mut rng = OsRandom;
        let material = SealMaterial {
            password: new,
            vault_id: header.vault_id,
            dek: slot_dek(self.slot.as_ref())?,
            kdf_salt: random_array_with::<16>(&mut rng)?,
            wrap_nonce: random_array_with::<24>(&mut rng)?,
            payload_nonce: random_array_with::<24>(&mut rng)?,
            generation: header.generation.checked_add(1).ok_or(INTERNAL)?,
            payload: &payload,
        };
        let bytes = format::seal_create_with(&material, &self.kdf)?;
        self.commit_vault(Some(header.generation), bytes)?;
        Ok(match self.rewrite_payload(&payload) {
            Ok(()) => PasswordChange::Complete,
            Err(_) => PasswordChange::PrevNotRefreshed,
        })
    }

    /// The mnemonic, after re-entering the password (spec/02 §9).
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`/`Unlocked`, or `UnlockFailed`.
    pub fn reveal_mnemonic(&self, password: &VaultPassword) -> Result<SecretString, VaultError> {
        self.require_public()?;
        self.verify_password(password)?;
        Ok(mnemonic_record(&self.payload()?)?.mnemonic.phrase()?)
    }

    /// An EVM private key as 64 lowercase hex digits without `0x`, after re-entering the password.
    ///
    /// # Errors
    ///
    /// `BackupNotConfirmed`/`InvalidState`, `UnlockFailed` or `RecordNotFound`.
    pub fn reveal_evm_private_key(
        &self,
        password: &VaultPassword,
        src: EvmKeySource,
    ) -> Result<SecretString, VaultError> {
        self.require_signing()?;
        self.verify_password(password)?;
        let payload = self.payload()?;
        Self::require_key_backup(&payload, KeyRef::Evm(src))?;
        let ctx = secp_context(&mut OsRandom)?;
        let mut secret = self.secret_for(&ctx, &payload, KeyRef::Evm(src))?;
        let raw = Zeroizing::new(secret.secret_bytes());
        secret.non_secure_erase();
        let mut out = Zeroizing::new(String::with_capacity(64));
        hex::encode_into(raw.as_slice(), &mut out);
        Ok(SecretString::from_zeroizing(out))
    }

    /// The address of one EVM key source.
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`/`Unlocked`, `RecordNotFound`, or a derivation error.
    pub fn evm_address(&self, src: EvmKeySource) -> Result<Address, VaultError> {
        self.require_public()?;
        let payload = self.payload()?;
        if let EvmKeySource::Hardware(index) = src {
            return hardware_evm_address(&payload, index);
        }
        let ctx = secp_context(&mut OsRandom)?;
        let mut secret = self.secret_for(&ctx, &payload, KeyRef::Evm(src))?;
        let public = PublicKey::from_secret_key(&ctx, &secret);
        secret.non_secure_erase();
        Ok(Address::from_public_key(&public))
    }

    /// The compressed public key of derived EVM account `index` (`m/44'/60'/0'/0/i`) for a
    /// Bitcoin account on the same key (spec/08 §3.5 "EVM 계정과 같은 키"). Public information; the
    /// key is erased on return.
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`/`Unlocked`, `NoMnemonic` for a key-only vault, or a
    /// derivation error.
    pub fn evm_public_key(&self, index: AccountIndex) -> Result<[u8; 33], VaultError> {
        self.require_public()?;
        let payload = self.payload()?;
        let ctx = secp_context(&mut OsRandom)?;
        let mut secret =
            self.secret_for(&ctx, &payload, KeyRef::Evm(EvmKeySource::Derived(index)))?;
        let public = PublicKey::from_secret_key(&ctx, &secret);
        secret.non_secure_erase();
        Ok(public.serialize())
    }

    /// The WIF of a Bitcoin account on EVM account `index`'s key (`m/44'/60'/0'/0/i`, compressed,
    /// `network`'s version byte) after re-entering the password (spec/08 §3.5; the same export
    /// rules as an imported key's WIF, spec/02 §9).
    ///
    /// # Errors
    ///
    /// `BackupNotConfirmed`/`InvalidState`, `UnlockFailed`, `NoMnemonic` or a derivation error.
    pub fn reveal_evm_shared_wif(
        &self,
        password: &VaultPassword,
        index: AccountIndex,
        network: crate::btc::BtcNetwork,
    ) -> Result<SecretString, VaultError> {
        self.require_signing()?;
        self.verify_password(password)?;
        let payload = self.payload()?;
        Self::require_key_backup(&payload, KeyRef::Evm(EvmKeySource::Derived(index)))?;
        let ctx = secp_context(&mut OsRandom)?;
        let mut secret =
            self.secret_for(&ctx, &payload, KeyRef::Evm(EvmKeySource::Derived(index)))?;
        let raw = Zeroizing::new(secret.secret_bytes());
        secret.non_secure_erase();
        Ok(crate::codec::wif::encode_wif(&raw, true, network))
    }

    /// Addresses of up to 100 derived accounts, computing the seed once.
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`/`Unlocked` or for more than 100 indices.
    pub fn evm_addresses(&self, indices: &[AccountIndex]) -> Result<Vec<Address>, VaultError> {
        self.require_public()?;
        if indices.len() > MAX_ADDRESS_BATCH {
            return Err(VaultError::InvalidState);
        }
        if indices.is_empty() {
            return Ok(Vec::new());
        }
        let payload = self.payload()?;
        let id = mnemonic_record(&payload)?.record_id;
        self.evm_addresses_from(&payload, &id, indices)
    }

    /// Addresses of up to 100 derived accounts of mnemonic `id` (any of the vault's mnemonics),
    /// computing its seed once.
    ///
    /// # Errors
    ///
    /// As [`Vault::evm_addresses`], and `RecordNotFound` for an unknown `id`.
    pub fn evm_addresses_of(
        &self,
        id: RecordId,
        indices: &[AccountIndex],
    ) -> Result<Vec<Address>, VaultError> {
        self.require_public()?;
        if indices.len() > MAX_ADDRESS_BATCH {
            return Err(VaultError::InvalidState);
        }
        let payload = self.payload()?;
        self.evm_addresses_from(&payload, &id.0, indices)
    }

    fn evm_addresses_from(
        &self,
        payload: &Payload,
        id: &[u8; 16],
        indices: &[AccountIndex],
    ) -> Result<Vec<Address>, VaultError> {
        if indices.is_empty() {
            return Ok(Vec::new());
        }
        let seed = self.seed_of(payload, id)?;
        let ctx = secp_context(&mut OsRandom)?;
        indices
            .iter()
            .map(|index| {
                evm_address_from_seed(&ctx, seed.expose(), *index).map_err(VaultError::from)
            })
            .collect()
    }

    /// Imported raw keys and their addresses, in payload order.
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`/`Unlocked`.
    pub fn raw_keys(&self) -> Result<Vec<(RecordId, Address)>, VaultError> {
        self.require_public()?;
        let payload = self.payload()?;
        let ctx = secp_context(&mut OsRandom)?;
        payload
            .raw_keys
            .iter()
            .map(|raw| {
                let mut secret = SecretKey::from_byte_array(*raw.key).map_err(|_| INTERNAL)?;
                let public = PublicKey::from_secret_key(&ctx, &secret);
                secret.non_secure_erase();
                Ok((RecordId(raw.record_id), Address::from_public_key(&public)))
            })
            .collect()
    }

    /// The Bitcoin account node `m/84'/{coin}'/0'` as public information (compressed public key
    /// and chain code, spec/02 §10.3, spec/08 §3.1). Addresses are derived from it with
    /// `bip32::derive_public_child`; the seed, private nodes and keys are wiped on return.
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`/`Unlocked`, or a derivation error.
    pub fn btc_account_xpub(&self, coin: BtcCoin) -> Result<AccountXpub, VaultError> {
        self.btc_account_xpub_of(None, coin)
    }

    /// [`Vault::btc_account_xpub`] of mnemonic `mnemonic` (`None`: the primary one; an added
    /// mnemonic's Bitcoin accounts, spec/02 §8.6).
    ///
    /// # Errors
    ///
    /// As [`Vault::btc_account_xpub`], and `RecordNotFound` for an unknown mnemonic.
    pub fn btc_account_xpub_of(
        &self,
        mnemonic: Option<RecordId>,
        coin: BtcCoin,
    ) -> Result<AccountXpub, VaultError> {
        self.require_public()?;
        let payload = self.payload()?;
        let seed = self.seed_for(&payload, mnemonic)?;
        let ctx = secp_context(&mut OsRandom)?;
        Ok(btc_account_xpub_from_seed(&ctx, seed.expose(), coin)?)
    }

    /// The compressed public key of `m/84'/{coin}'/0'/{chain}/{index}` by private derivation
    /// (spec/02 §10.3), for cross-checking the public (`CKDpub`) derivation (spec/08 §14.1).
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`/`Unlocked`, `Key(InvalidPath)` for a hardened
    /// `index`, or a derivation error.
    pub fn btc_public_key(
        &self,
        coin: BtcCoin,
        chain: BtcChain,
        index: u32,
    ) -> Result<[u8; 33], VaultError> {
        self.require_public()?;
        btc_path(coin, chain, index)?;
        let payload = self.payload()?;
        let ctx = secp_context(&mut OsRandom)?;
        let mut secret = self.secret_for(
            &ctx,
            &payload,
            KeyRef::Btc {
                mnemonic: None,
                coin,
                chain,
                index,
            },
        )?;
        let public = PublicKey::from_secret_key(&ctx, &secret);
        secret.non_secure_erase();
        Ok(public.serialize())
    }

    /// The compressed public key of the Zcash transparent key `m/44'/{133|1}'/{account}'/0/{index}`
    /// (public information, spec/12 §2.2; the private key is wiped on return).
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`/`Unlocked`, `NoMnemonic` for a key-only vault,
    /// `Key(InvalidPath)` for a hardened index, or a derivation error.
    pub fn zec_public_key(
        &self,
        test: bool,
        account: u32,
        index: u32,
    ) -> Result<[u8; 33], VaultError> {
        self.zec_public_key_of(None, test, account, index)
    }

    /// [`Vault::zec_public_key`] of mnemonic `mnemonic` (`None`: the primary one; an added
    /// mnemonic's Zcash key, spec/02 §8.6).
    ///
    /// # Errors
    ///
    /// As [`Vault::zec_public_key`], and `RecordNotFound` for an unknown mnemonic.
    pub fn zec_public_key_of(
        &self,
        mnemonic: Option<RecordId>,
        test: bool,
        account: u32,
        index: u32,
    ) -> Result<[u8; 33], VaultError> {
        self.require_public()?;
        crate::bip32::path::zec_path(test, account, index)?;
        let payload = self.payload()?;
        let ctx = secp_context(&mut OsRandom)?;
        let mut secret = self.secret_for(
            &ctx,
            &payload,
            KeyRef::Zec {
                mnemonic,
                test,
                account,
                index,
            },
        )?;
        let public = PublicKey::from_secret_key(&ctx, &secret);
        secret.non_secure_erase();
        Ok(public.serialize())
    }

    /// Whether the vault has recovery words (`false` for a key-only vault, spec/02 §4.6).
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`/`Unlocked`.
    pub fn has_mnemonic(&self) -> Result<bool, VaultError> {
        self.require_public()?;
        Ok(!self.payload()?.bip39.is_empty())
    }

    /// The vault's recovery phrases in payload order (the first is the primary one).
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`/`Unlocked`.
    pub fn mnemonics(&self) -> Result<Vec<MnemonicInfo>, VaultError> {
        self.require_public()?;
        Ok(self
            .payload()?
            .bip39
            .iter()
            .enumerate()
            .map(|(position, record)| MnemonicInfo {
                id: RecordId(record.record_id),
                created_unix: record.created_unix,
                words: record.mnemonic.word_count().words(),
                passphrase_used: record.passphrase_used,
                backup_confirmed: record.backup_confirmed,
                primary: position == 0,
            })
            .collect())
    }

    /// Adds an existing recovery phrase ("복구 단어 추가 가져오기", spec/02 §8.6) after
    /// re-entering the password: backup counts as confirmed; a passphrase is checked like at
    /// import and kept in the slot for this session (asked again at each unlock). A key-only or
    /// `YubiKey` vault's first phrase becomes its primary mnemonic. `PayloadRewrite`.
    ///
    /// # Errors
    ///
    /// `BackupNotConfirmed`/`InvalidState`, `UnlockFailed`, the mnemonic and passphrase
    /// `KeyError`s, `DuplicateKey` (the same seed — phrase and passphrase — is already in the
    /// vault; compared in constant time), `RecordLimit` (8 mnemonics), `RandomnessUnavailable`
    /// or `Storage`.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "spec/02 §10.3: the passphrase moves into the vault and is wiped on return"
    )]
    pub fn add_mnemonic(
        &mut self,
        password: &VaultPassword,
        phrase: &str,
        passphrase: Option<Bip39Passphrase>,
        now_unix: u64,
    ) -> Result<RecordId, VaultError> {
        self.require_signing()?;
        self.verify_password(password)?;
        let mnemonic = Mnemonic::parse(phrase)?;
        if passphrase.as_ref().is_some_and(Bip39Passphrase::is_empty) {
            return Err(KeyError::PassphraseEmpty.into());
        }
        let mut payload = self.payload()?;
        if payload.bip39.len() >= MAX_MNEMONICS {
            return Err(VaultError::RecordLimit);
        }
        let empty = Bip39Passphrase::empty();
        let seed = mnemonic.to_seed(passphrase.as_ref().unwrap_or(&empty))?;
        let mut duplicate = 0_u8;
        for record in &payload.bip39 {
            let other = self.seed_of(&payload, &record.record_id)?;
            duplicate |= other.expose().ct_eq(seed.expose()).unwrap_u8();
        }
        drop(seed);
        if duplicate != 0 {
            return Err(VaultError::DuplicateKey);
        }
        let passphrase_check = match &passphrase {
            Some(value) => passphrase_check(&address_zero(
                &secp_context(&mut OsRandom)?,
                &mnemonic,
                value,
            )?),
            None => [0; 4],
        };
        let record_id = fresh_record_id(&mut OsRandom, &payload)?;
        let primary = payload.bip39.is_empty();
        payload.bip39.push(Bip39Record {
            record_id,
            created_unix: now_unix,
            mnemonic,
            passphrase_used: passphrase.is_some(),
            backup_confirmed: true,
            passphrase_check,
        });
        self.rewrite_payload(&payload)?;
        let slot = self.slot.as_mut().ok_or(VaultError::InvalidState)?;
        set_record_passphrase(slot.as_mut(), &record_id, primary, passphrase.as_ref())?;
        Ok(RecordId(record_id))
    }

    /// Makes a new 24-word recovery phrase ("새 복구 단어 만들기 (추가)", spec/02 §8.6) after
    /// re-entering the password and returns it for the first display. Its backup is open until
    /// [`Vault::confirm_backup_for`]: signing with its accounts is refused until then.
    ///
    /// # Errors
    ///
    /// `BackupNotConfirmed`/`InvalidState`, `UnlockFailed`, `RecordLimit`,
    /// `RandomnessUnavailable` or `Storage`.
    pub fn generate_mnemonic(
        &mut self,
        password: &VaultPassword,
        now_unix: u64,
    ) -> Result<(RecordId, SecretString), VaultError> {
        self.require_signing()?;
        self.verify_password(password)?;
        let mut payload = self.payload()?;
        if payload.bip39.len() >= MAX_MNEMONICS {
            return Err(VaultError::RecordLimit);
        }
        let mnemonic = Mnemonic::generate_with_rng(&mut OsRandom)?;
        let phrase = mnemonic.phrase()?;
        let record_id = fresh_record_id(&mut OsRandom, &payload)?;
        payload.bip39.push(Bip39Record {
            record_id,
            created_unix: now_unix,
            mnemonic,
            passphrase_used: false,
            backup_confirmed: false,
            passphrase_check: [0; 4],
        });
        self.rewrite_payload(&payload)?;
        Ok((RecordId(record_id), phrase))
    }

    /// Removes an added recovery phrase after re-entering the password (spec/02 §8.6). The
    /// primary (first) one cannot be removed: the existing account lists come from it.
    ///
    /// # Errors
    ///
    /// `BackupNotConfirmed`/`InvalidState`, `UnlockFailed`, `RecordNotFound`,
    /// `PrimaryMnemonic` or `Storage`.
    pub fn remove_mnemonic(
        &mut self,
        password: &VaultPassword,
        id: RecordId,
    ) -> Result<(), VaultError> {
        self.require_signing()?;
        self.verify_password(password)?;
        let mut payload = self.payload()?;
        let primary = record_of(&payload, &id.0)?.1;
        if primary {
            return Err(VaultError::PrimaryMnemonic);
        }
        payload.bip39.retain(|record| record.record_id != id.0);
        self.rewrite_payload(&payload)?;
        if let Some(slot) = self.slot.as_mut() {
            set_record_passphrase(slot.as_mut(), &id.0, false, None)?;
        }
        if matches!(self.challenge, Some((_, _, target)) if target == id.0) {
            self.challenge = None;
        }
        Ok(())
    }

    /// The words of mnemonic `id`, after re-entering the password (spec/02 §9).
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`/`Unlocked`, `UnlockFailed` or `RecordNotFound`.
    pub fn reveal_mnemonic_of(
        &self,
        password: &VaultPassword,
        id: RecordId,
    ) -> Result<SecretString, VaultError> {
        self.require_public()?;
        self.verify_password(password)?;
        Ok(record_of(&self.payload()?, &id.0)?.0.mnemonic.phrase()?)
    }

    /// Whether the vault holds an imported Bitcoin key (`tag 4`) with record id `id` (the vault
    /// is the source of truth for imported-key accounts, spec/02 §10.3).
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`/`Unlocked`.
    pub fn has_btc_key(&self, id: RecordId) -> Result<bool, VaultError> {
        self.require_public()?;
        Ok(self
            .payload()?
            .btc_keys
            .iter()
            .any(|record| record.record_id == id.0))
    }

    /// Public facts of every imported key (EVM addresses, Solana public keys, Bitcoin addresses
    /// with their script type and network), in payload order (spec/02 §10.3).
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`/`Unlocked`.
    pub fn imported_keys(&self) -> Result<ImportedKeys, VaultError> {
        self.require_public()?;
        let payload = self.payload()?;
        let ctx = secp_context(&mut OsRandom)?;
        let mut evm = Vec::with_capacity(payload.raw_keys.len());
        for raw in &payload.raw_keys {
            let mut secret = SecretKey::from_byte_array(*raw.key).map_err(|_| INTERNAL)?;
            let public = PublicKey::from_secret_key(&ctx, &secret);
            secret.non_secure_erase();
            evm.push((RecordId(raw.record_id), Address::from_public_key(&public)));
        }
        let sol = payload
            .sol_keys
            .iter()
            .map(|sol| (RecordId(sol.record_id), sol.public))
            .collect();
        let mut btc = Vec::with_capacity(payload.btc_keys.len());
        for record in &payload.btc_keys {
            let info = btc_info(
                &record.secret,
                record.compressed,
                record.network,
                record.script,
            )?;
            btc.push((RecordId(record.record_id), info));
        }
        let mut zec = Vec::with_capacity(payload.zec_keys.len());
        for record in &payload.zec_keys {
            let info = crate::keyimport::zec_info(&record.secret, record.network)?;
            zec.push((RecordId(record.record_id), info));
        }
        Ok(ImportedKeys {
            has_mnemonic: !payload.bip39.is_empty(),
            evm,
            sol,
            btc,
            zec,
        })
    }

    /// The export text of an imported key after re-entering the password (spec/02 §9): EVM 64
    /// lowercase hex (no `0x`), Solana the base58 64-byte keypair, Bitcoin the WIF, Zcash the
    /// compressed WIF.
    ///
    /// # Errors
    ///
    /// `BackupNotConfirmed`/`InvalidState`, `UnlockFailed` or `RecordNotFound`.
    pub fn reveal_imported_key(
        &self,
        password: &VaultPassword,
        id: RecordId,
    ) -> Result<(ImportChain, SecretString), VaultError> {
        self.require_signing()?;
        self.verify_password(password)?;
        let payload = self.payload()?;
        if let Some(raw) = payload.raw_keys.iter().find(|raw| raw.record_id == id.0) {
            let mut out = Zeroizing::new(String::with_capacity(64));
            hex::encode_into(raw.key.as_slice(), &mut out);
            return Ok((ImportChain::Evm, SecretString::from_zeroizing(out)));
        }
        if let Some(sol) = payload.sol_keys.iter().find(|sol| sol.record_id == id.0) {
            return Ok((
                ImportChain::Sol,
                crate::keyimport::sol::encode_keypair(&sol.seed, &sol.public),
            ));
        }
        if let Some(btc) = payload.btc_keys.iter().find(|btc| btc.record_id == id.0) {
            return Ok((
                ImportChain::Btc,
                crate::codec::wif::encode_wif(&btc.secret, btc.compressed, btc.network),
            ));
        }
        if let Some(zec) = payload.zec_keys.iter().find(|zec| zec.record_id == id.0) {
            // Zcash uses the Bitcoin WIF versions (0x80 / 0xEF) and the compressed key.
            let version = match zec.network {
                crate::zec::ZecNetwork::Mainnet => crate::btc::BtcNetwork::Mainnet,
                crate::zec::ZecNetwork::Testnet => crate::btc::BtcNetwork::Testnet4,
            };
            return Ok((
                ImportChain::Zec,
                crate::codec::wif::encode_wif(&zec.secret, true, version),
            ));
        }
        Err(VaultError::RecordNotFound)
    }

    /// Creates a key-only vault (no recovery words) holding one imported key (spec/02 §8.5):
    /// `Create`, then `Unlocked { alt: false }` — there is no passphrase and no backup step (the
    /// backup is the original private key). Returns the key's record id.
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `NoVault`, `RandomnessUnavailable`, `OutOfMemory` or `Storage`.
    /// On failure the state stays `NoVault` and the slot is wiped.
    pub fn create_with_key(
        &mut self,
        password: &VaultPassword,
        key: ImportKey,
        slot: Slot,
        now_unix: u64,
    ) -> Result<RecordId, VaultError> {
        self.create_with_key_rng(&mut OsRandom, password, key, slot, now_unix)
    }

    pub(crate) fn create_with_key_rng(
        &mut self,
        rng: &mut impl RandomSource,
        password: &VaultPassword,
        key: ImportKey,
        slot: Slot,
        now_unix: u64,
    ) -> Result<RecordId, VaultError> {
        self.create_without_mnemonic(rng, password, slot, |payload, record_id| {
            add_key(payload, key, record_id, now_unix)
        })
    }

    /// `Create` of a vault without recovery words whose first record `fill` adds (a key-only
    /// vault, spec/02 §8.5, or a `YubiKey` vault, spec/10 §8.2).
    fn create_without_mnemonic(
        &mut self,
        rng: &mut impl RandomSource,
        password: &VaultPassword,
        slot: Slot,
        fill: impl FnOnce(&mut Payload, [u8; 16]) -> Result<(), VaultError>,
    ) -> Result<RecordId, VaultError> {
        if self.status != VaultStatus::NoVault {
            wipe_and_drop(slot);
            return Err(VaultError::InvalidState);
        }
        let sealed = (|| -> Result<_, VaultError> {
            let dek = random_secret32_with(rng)?;
            let vault_id = random_nonzero_id_with(rng)?;
            let record_id = random_nonzero_id_with(rng)?;
            let kdf_salt = random_array_with::<16>(rng)?;
            let wrap_nonce = random_array_with::<24>(rng)?;
            let payload_nonce = random_array_with::<24>(rng)?;
            let mut payload = Payload::new(None);
            fill(&mut payload, record_id)?;
            let material = SealMaterial {
                password,
                vault_id,
                dek: &dek,
                kdf_salt,
                wrap_nonce,
                payload_nonce,
                generation: 1,
                payload: &payload,
            };
            Ok((
                format::seal_create_with(&material, &self.kdf)?,
                dek,
                vault_id,
                record_id,
            ))
        })();
        let (bytes, dek, vault_id, record_id) = match sealed {
            Ok(values) => values,
            Err(error) => {
                wipe_and_drop(slot);
                return Err(error);
            }
        };
        if let Err(error) = commit_landed(self.storage.as_mut(), FileKind::Vault, None, &bytes) {
            wipe_and_drop(slot);
            return Err(VaultError::Storage(error));
        }
        self.ciphertext = Some(bytes);
        self.id = Some(vault_id);
        self.open_session(slot, &dek, None)?;
        self.status = VaultStatus::Unlocked {
            alt_passphrase: false,
        };
        Ok(RecordId(record_id))
    }

    /// Lends the seed of the imported Solana key whose public key is `public` to the Solana
    /// signing module (`Unlocked` only, spec/02 §10.3). The seed is wiped when `f` returns.
    pub(crate) fn with_imported_ed25519_seed<T>(
        &self,
        public: &[u8; 32],
        f: impl FnOnce(&[u8; 32]) -> Result<T, VaultError>,
    ) -> Result<T, VaultError> {
        self.require_signing()?;
        let payload = self.payload()?;
        let record = payload
            .sol_keys
            .iter()
            .find(|sol| sol.public == *public)
            .ok_or(VaultError::RecordNotFound)?;
        let mut seed = Zeroizing::new([0_u8; 32]);
        seed.copy_from_slice(record.seed.as_slice());
        drop(payload);
        f(&seed)
    }

    /// The signing secret of imported Bitcoin key `id` (vault tag 4) with the record's
    /// compression flag, network and address type, for the Bitcoin signer only
    /// (`btc::sign::BtcImportedKeys`, spec/08 §11.1; `Unlocked` only). The decrypted payload is
    /// wiped when this returns; the returned secret is crate-internal (no accessor outside
    /// `btc::sign`, which lends it to its signing closure) and erased on drop.
    ///
    /// # Errors
    ///
    /// `BackupNotConfirmed`/`InvalidState` (locked), `RecordNotFound` (no tag-4 record `id`).
    pub(crate) fn imported_btc_secret(
        &self,
        id: &[u8; 16],
    ) -> Result<crate::btc::sign::ImportedBtcSecret, VaultError> {
        self.require_signing()?;
        let payload = self.payload()?;
        let record = payload
            .btc_keys
            .iter()
            .find(|btc| btc.record_id == *id)
            .ok_or(VaultError::RecordNotFound)?;
        let secret = SecretKey::from_byte_array(*record.secret).map_err(|_| INTERNAL)?;
        Ok(crate::btc::sign::ImportedBtcSecret::new(
            secret,
            record.compressed,
            record.network,
            record.script,
        ))
    }

    fn set_known(&self, index: usize, value: Known) {
        let mut known = self.sidecar_generations.get();
        if let Some(entry) = known.get_mut(index) {
            *entry = value;
        }
        self.sidecar_generations.set(known);
    }

    /// Opens `meta.ywm` or `journal.ywj`; `None` if the file does not exist. A structure or
    /// authentication failure blocks [`Vault::save_sidecar`] for that file until a later open
    /// succeeds (after the user restored `.prev` or quarantined the file).
    ///
    /// # Errors
    ///
    /// `InvalidState` (also for `FileKind::Vault`), `SidecarCorrupt`, `SidecarVaultMismatch`, `Storage`.
    pub fn open_sidecar(&self, kind: FileKind) -> Result<Option<SidecarContents>, VaultError> {
        self.require_public()?;
        let index = sidecar_index(kind)?;
        let vault_id = self.id.ok_or(VaultError::InvalidState)?;
        let dek = slot_dek(self.slot.as_ref())?;
        let opened = match self.storage.load(kind).map_err(VaultError::Storage)? {
            None => None,
            Some(bytes) => match format::open_sidecar(kind, &bytes, &vault_id, dek) {
                Ok((generation, plaintext)) => {
                    Some((generation, SecretVec::from_zeroizing(plaintext)))
                }
                Err(error) => {
                    if matches!(
                        error,
                        VaultError::SidecarCorrupt(_) | VaultError::SidecarVaultMismatch(_)
                    ) {
                        self.set_known(index, Known::Failed(error));
                    }
                    return Err(error);
                }
            },
        };
        self.set_known(
            index,
            Known::from_option(opened.as_ref().map(|(generation, _)| *generation)),
        );
        Ok(opened)
    }

    /// Seals and commits a sidecar with generation CAS against the last generation seen.
    /// Returns the new generation. A file not yet opened in this session is opened (and so
    /// authenticated) first: a file that fails is never overwritten.
    ///
    /// # Errors
    ///
    /// `InvalidState` (also for `FileKind::Vault`), `SidecarCorrupt`/`SidecarVaultMismatch` while
    /// the file failed to open, `Storage(GenerationConflict)` and other storage errors,
    /// `Storage(TooLarge)` above the plaintext bound.
    pub fn save_sidecar(&mut self, kind: FileKind, plaintext: &[u8]) -> Result<u64, VaultError> {
        self.require_public()?;
        let index = sidecar_index(kind)?;
        let vault_id = self.id.ok_or(VaultError::InvalidState)?;
        let known = self.sidecar_generations.get();
        let expected = match known.get(index).copied().unwrap_or(Known::Unknown) {
            Known::Generation(last) => Some(last),
            Known::Absent => None,
            Known::Failed(error) => return Err(error),
            Known::Unknown => self.open_sidecar(kind)?.map(|(generation, _)| generation),
        };
        let generation = expected
            .map_or(Some(1), |last| last.checked_add(1))
            .ok_or(INTERNAL)?;
        let nonce = random_array_with::<24>(&mut OsRandom)?;
        let bytes = format::seal_sidecar(
            kind,
            &vault_id,
            generation,
            &nonce,
            slot_dek(self.slot.as_ref())?,
            plaintext,
        )?;
        commit_landed(self.storage.as_mut(), kind, expected, &bytes)
            .map_err(VaultError::Storage)?;
        self.set_known(index, Known::Generation(generation));
        Ok(generation)
    }

    /// Lends a signing key to the chain modules (`Unlocked` only). The key is erased afterwards.
    pub(crate) fn with_secp_key<T>(
        &self,
        key: KeyRef,
        f: impl FnOnce(&Secp256k1<All>, &SecretKey) -> Result<T, VaultError>,
    ) -> Result<T, VaultError> {
        self.require_signing()?;
        let payload = self.payload()?;
        Self::require_key_backup(&payload, key)?;
        let ctx = secp_context(&mut OsRandom)?;
        let mut secret = self.secret_for(&ctx, &payload, key)?;
        let result = f(&ctx, &secret);
        secret.non_secure_erase();
        result
    }

    /// Ed25519 public keys of up to 128 Solana key sources, computing the BIP39 seed once
    /// (spec/02 §10.3; account add, cache refresh, recovery scan). Output order = input order;
    /// each source's seed is wiped right after its public key is computed.
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`/`Unlocked` or for more than 128 sources (nothing is
    /// derived), `Key(InvalidPath)` for `SolletLegacy` (not implemented, spec/07 §3.2).
    pub fn sol_public_keys(&self, srcs: &[SolKeySource]) -> Result<Vec<[u8; 32]>, VaultError> {
        self.require_public()?;
        if srcs.len() > MAX_SOL_KEY_BATCH {
            return Err(VaultError::InvalidState);
        }
        if srcs.is_empty() {
            return Ok(Vec::new());
        }
        let payload = self.payload()?;
        // `YubiKey` sources come from the tag-5 slot map; each mnemonic's BIP39 seed is computed
        // once, only when a derived source of it asks for it (a `YubiKey` wallet has no
        // mnemonic; an added mnemonic's accounts use its own seed, spec/02 §8.6).
        let mut seeds: Vec<(Option<RecordId>, SecretBytes<64>)> = Vec::new();
        let mut out = Vec::with_capacity(srcs.len());
        for src in srcs {
            if let SolKeySource::Hardware(index) = src {
                out.push(hardware_sol_public_key(&payload, *index)?);
                continue;
            }
            let id = src.mnemonic();
            let position = match seeds.iter().position(|(known, _)| *known == id) {
                Some(position) => position,
                None => {
                    seeds.push((id, self.seed_for(&payload, id)?));
                    seeds.len().saturating_sub(1)
                }
            };
            let seed = seeds.get(position).ok_or(INTERNAL)?;
            let secret = src.ed25519_seed(seed.1.expose())?;
            out.push(crate::sol::keys::public_key(&secret));
        }
        Ok(out)
    }

    /// Lends the 32-byte Ed25519 seed of `src` to the Solana signing module (`Unlocked` only).
    /// The seed, the BIP39 seed and every intermediate are wiped when `f` returns
    /// (spec/02 §10.3, §7.3).
    pub(crate) fn with_ed25519_seed<T>(
        &self,
        src: SolKeySource,
        f: impl FnOnce(&[u8; 32]) -> Result<T, VaultError>,
    ) -> Result<T, VaultError> {
        self.require_signing()?;
        // A YubiKey account has no key on the PC (spec/10 §1).
        if src.is_hardware() {
            return Err(VaultError::RecordNotFound);
        }
        let payload = self.payload()?;
        // The backup gate of the source's own mnemonic (spec/02 §8.6).
        let record = match src.mnemonic() {
            Some(id) => Some(record_of(&payload, id.as_bytes())?.0),
            None => payload.primary(),
        };
        if record.is_some_and(|record| !record.backup_confirmed) {
            return Err(VaultError::BackupNotConfirmed);
        }
        let seed = self.seed_for(&payload, src.mnemonic())?;
        let secret = src.ed25519_seed(seed.expose())?;
        drop(seed);
        drop(payload);
        f(&secret)
    }

    #[cfg(test)]
    pub(crate) fn slot_bytes(&self) -> Option<&[u8; SLOT_LEN]> {
        self.slot.as_ref().map(|slot| slot.bytes())
    }

    #[cfg(test)]
    pub(crate) fn held_bytes(&self) -> Option<&[u8]> {
        self.ciphertext.as_deref()
    }
}

/// One enrolled `YubiKey` as stored in the vault (tag 5, spec/10 §8): public data only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardwareKey {
    /// Record id.
    pub id: RecordId,
    /// Enrolment time (Unix seconds, from yw-app).
    pub created_unix: u64,
    /// Serial, firmware, fingerprint and slot map.
    pub record: HwKeyRecord,
}

/// The address of `YubiKey` EVM account `index` from the slot map (`RecordNotFound` when no card
/// holds it).
fn hardware_evm_address(payload: &Payload, index: AccountIndex) -> Result<Address, VaultError> {
    let role = crate::yubikey::plan::KeyRole::Evm { index, btc: None };
    let identity = role.key_identity();
    payload
        .hw_keys
        .iter()
        .flat_map(|entry| &entry.record.slots)
        .find(|slot| slot.role.key_identity() == identity)
        .ok_or(VaultError::RecordNotFound)
        .and_then(|slot| crate::yubikey::plan::evm_address(&slot.public).map_err(|_| INTERNAL))
}

/// The Ed25519 public key of `YubiKey` Solana account `index` from the slot map
/// (`RecordNotFound` when no card holds it).
fn hardware_sol_public_key(payload: &Payload, index: AccountIndex) -> Result<[u8; 32], VaultError> {
    let identity = crate::yubikey::plan::KeyRole::Sol { index }.key_identity();
    payload
        .hw_keys
        .iter()
        .flat_map(|entry| &entry.record.slots)
        .find(|slot| slot.role.key_identity() == identity)
        .ok_or(VaultError::RecordNotFound)
        .and_then(|slot| {
            crate::yubikey::plan::sol_address(&slot.public)
                .map(crate::sol::SolAddress::to_bytes)
                .map_err(|_| INTERNAL)
        })
}

/// The compressed public key of a `YubiKey` Bitcoin key from the slot map: `key` names the slot
/// role (a Bitcoin address key of `network`/`script_type`, or an EVM key used as one Bitcoin
/// address). `RecordNotFound` when no card holds it.
fn hardware_btc_public_key(
    payload: &Payload,
    network: crate::btc::BtcNetwork,
    script_type: crate::btc::account::ScriptType,
    key: crate::btc::account::HwBtcKey,
) -> Result<[u8; 33], VaultError> {
    let identity = key
        .role(network, script_type)
        .ok_or(VaultError::RecordNotFound)?
        .key_identity();
    payload
        .hw_keys
        .iter()
        .flat_map(|entry| &entry.record.slots)
        .find(|slot| slot.role.key_identity() == identity)
        .ok_or(VaultError::RecordNotFound)
        .and_then(|slot| match slot.public {
            crate::yubikey::record::HwPublicKey::Secp256k1(public) => Ok(public),
            crate::yubikey::record::HwPublicKey::Ed25519(_) => Err(INTERNAL),
        })
}

/// Adds a hardware key reference (one per serial, at most 8, consistent with the others).
fn add_hardware(
    payload: &mut Payload,
    record: HwKeyRecord,
    record_id: [u8; 16],
    now_unix: u64,
) -> Result<(), VaultError> {
    if payload
        .hw_keys
        .iter()
        .any(|entry| entry.record.serial == record.serial)
    {
        return Err(VaultError::DuplicateKey);
    }
    if payload.hw_keys.len() >= format::MAX_HW_KEYS {
        return Err(VaultError::RecordLimit);
    }
    let mut all: Vec<HwKeyRecord> = payload
        .hw_keys
        .iter()
        .map(|entry| entry.record.clone())
        .collect();
    all.push(record.clone());
    if !record.is_valid() || !records_consistent(&all) {
        return Err(VaultError::Key(KeyError::DerivationFailed));
    }
    payload.hw_keys.push(HwKeyEntry {
        record_id,
        created_unix: now_unix,
        record,
    });
    Ok(())
}

/// `YubiKey` accounts (spec/10 §8): the vault keeps only public slot maps.
impl Vault {
    /// The enrolled `YubiKeys` in payload order.
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`/`Unlocked`.
    pub fn hardware_keys(&self) -> Result<Vec<HardwareKey>, VaultError> {
        self.require_public()?;
        Ok(self
            .payload()?
            .hw_keys
            .iter()
            .map(|entry| HardwareKey {
                id: RecordId(entry.record_id),
                created_unix: entry.created_unix,
                record: entry.record.clone(),
            })
            .collect())
    }

    /// The Bitcoin account of a `YubiKey` key (spec/10 §3.1, §3.3): one fixed address whose
    /// compressed public key comes from the tag-5 slot map (never from the seed). `key` is a
    /// Bitcoin address key (`m/{44|49|84}'/{coin}'/0'/0/i` of `network` and `script_type`) or an
    /// EVM key (`m/44'/60'/0'/0/i`) used as one `script_type` address.
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`/`Unlocked`, `RecordNotFound` when no enrolled
    /// card holds the key (also for Taproot, which a card cannot hold).
    pub fn hardware_btc_account(
        &self,
        network: crate::btc::BtcNetwork,
        script_type: crate::btc::account::ScriptType,
        key: crate::btc::account::HwBtcKey,
    ) -> Result<crate::btc::account::BtcAccountKey, VaultError> {
        self.require_public()?;
        let payload = self.payload()?;
        let public = hardware_btc_public_key(&payload, network, script_type, key)?;
        crate::btc::account::BtcAccountKey::hardware(key, script_type, public)
            .map_err(|_| VaultError::RecordNotFound)
    }

    /// Adds an enrolled `YubiKey` (`PayloadRewrite`, no password: nothing secret is added).
    ///
    /// # Errors
    ///
    /// `BackupNotConfirmed`/`InvalidState`, `DuplicateKey` (serial already enrolled),
    /// `RecordLimit` (8 cards), `Key(DerivationFailed)` for a record that contradicts the
    /// enrolled ones (another fingerprint, or another public key for the same path),
    /// `RandomnessUnavailable` or `Storage`.
    pub fn add_hardware_key(
        &mut self,
        record: HwKeyRecord,
        now_unix: u64,
    ) -> Result<RecordId, VaultError> {
        self.require_signing()?;
        let mut payload = self.payload()?;
        let record_id = fresh_record_id(&mut OsRandom, &payload)?;
        add_hardware(&mut payload, record, record_id, now_unix)?;
        self.rewrite_payload(&payload)?;
        Ok(RecordId(record_id))
    }

    /// Removes an enrolled `YubiKey` after re-entering the password. The last record of a vault
    /// without recovery words cannot be removed (`LastKey`).
    ///
    /// # Errors
    ///
    /// `BackupNotConfirmed`/`InvalidState`, `UnlockFailed`, `RecordNotFound`, `LastKey` or
    /// `Storage`.
    pub fn remove_hardware_key(
        &mut self,
        password: &VaultPassword,
        id: RecordId,
    ) -> Result<(), VaultError> {
        self.require_signing()?;
        self.verify_password(password)?;
        let mut payload = self.payload()?;
        let before = payload.hw_keys.len();
        payload.hw_keys.retain(|entry| entry.record_id != id.0);
        if payload.hw_keys.len() == before {
            return Err(VaultError::RecordNotFound);
        }
        if payload.record_count() == 0 {
            return Err(VaultError::LastKey);
        }
        self.rewrite_payload(&payload)
    }

    /// The payload with record `id` replaced by `record` (`None`: removed), after the tag-5
    /// rules: same serial, a valid record consistent with the other cards, and a vault without
    /// recovery words keeps at least one record (`LastKey`).
    fn replaced_hardware(
        &self,
        id: RecordId,
        record: Option<&HwKeyRecord>,
    ) -> Result<Payload, VaultError> {
        let mut payload = self.payload()?;
        let position = payload
            .hw_keys
            .iter()
            .position(|entry| entry.record_id == id.0)
            .ok_or(VaultError::RecordNotFound)?;
        if let Some(record) = record {
            let entry = payload
                .hw_keys
                .get_mut(position)
                .ok_or(VaultError::RecordNotFound)?;
            if entry.record.serial != record.serial {
                return Err(VaultError::Key(KeyError::DerivationFailed));
            }
            entry.record = record.clone();
            let all: Vec<HwKeyRecord> = payload
                .hw_keys
                .iter()
                .map(|entry| entry.record.clone())
                .collect();
            if !record.is_valid() || !records_consistent(&all) {
                return Err(VaultError::Key(KeyError::DerivationFailed));
            }
        } else {
            payload.hw_keys.remove(position);
            if payload.record_count() == 0 {
                return Err(VaultError::LastKey);
            }
        }
        Ok(payload)
    }

    /// Whether [`Vault::replace_hardware_key`] would accept the change (checked before a card is
    /// changed, spec/10 §15).
    ///
    /// # Errors
    ///
    /// As [`Vault::replace_hardware_key`], without writing.
    pub fn check_replace_hardware_key(
        &self,
        id: RecordId,
        record: Option<&HwKeyRecord>,
    ) -> Result<(), VaultError> {
        self.require_signing()?;
        self.replaced_hardware(id, record).map(drop)
    }

    /// Replaces the slot map of an enrolled `YubiKey` after "슬롯 구성 바꾸기" or
    /// "`YubiKey` 비우기" (spec/10 §15; `PayloadRewrite`, no password: the card was already changed with
    /// its own PIN, and nothing secret is involved). `None` removes the record (a card with no
    /// wallet slot left).
    ///
    /// # Errors
    ///
    /// `BackupNotConfirmed`/`InvalidState`, `RecordNotFound`, `Key(DerivationFailed)` (another
    /// serial, an invalid record or one contradicting the other cards), `LastKey` or `Storage`.
    pub fn replace_hardware_key(
        &mut self,
        id: RecordId,
        record: Option<&HwKeyRecord>,
    ) -> Result<(), VaultError> {
        self.require_signing()?;
        let payload = self.replaced_hardware(id, record)?;
        self.rewrite_payload(&payload)
    }

    /// Creates a `YubiKey` vault (no recovery words, spec/10 §8.2) holding the first enrolled
    /// card: `Create`, then `Unlocked { alt: false }`. The mnemonic the keys came from is the
    /// paper backup and is never stored.
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `NoVault`, `Key(DerivationFailed)` for an invalid record,
    /// `RandomnessUnavailable`, `OutOfMemory` or `Storage`. On failure the state stays
    /// `NoVault` and the slot is wiped.
    pub fn create_with_hardware(
        &mut self,
        password: &VaultPassword,
        record: HwKeyRecord,
        slot: Slot,
        now_unix: u64,
    ) -> Result<RecordId, VaultError> {
        self.create_without_mnemonic(&mut OsRandom, password, slot, |payload, record_id| {
            add_hardware(payload, record, record_id, now_unix)
        })
    }
}

/// Dropping the vault (worker shutdown, a replaced `Load`, a panic-free early return) locks it:
/// the slot is zeroized before it is released, as on [`Vault::lock`].
impl Drop for Vault {
    fn drop(&mut self) {
        self.lock();
    }
}
