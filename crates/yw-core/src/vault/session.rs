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
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

use super::format::{self, Bip39Record, MAX_RAW_KEYS, Payload, RawKeyRecord, SealMaterial};
use super::{
    BackupChallenge, ChallengeId, EvmKeySource, FileKind, KDF_V3, KdfParams, KeyRef, LockedSlot,
    RecordId, SLOT_LEN, VaultStatus, VaultStorage,
};
use crate::bip32::path::{AccountIndex, btc_path, evm_path};
use crate::bip32::{evm_address_from_seed, secret_key_from_seed};
use crate::bip39::Mnemonic;
use crate::entropy::{
    OsRandom, RandomSource, random_array_with, random_below_with, random_nonzero_id_with,
    random_secret32_with, secp_context,
};
use crate::error::{KeyError, StorageError, VaultError};
use crate::evm::Address;
use crate::hex;
use crate::password::{Bip39Passphrase, VaultPassword};

const MAX_ADDRESS_BATCH: usize = 100;
const CHALLENGE_WORDS: usize = 4;
const MAX_BACKUP_WORD: usize = 8;
const ADDRESS_SUFFIX_LEN: usize = 6;
const SLOT_DEK_END: usize = 32;
const SLOT_FLAG: usize = 32;
const SLOT_PASSPHRASE_LEN: usize = 33;
const SLOT_PASSPHRASE: usize = 35;
const SLOT_PASSPHRASE_END: usize = 291;
const INTERNAL: VaultError = VaultError::Key(KeyError::Internal);

type Slot = Box<dyn LockedSlot>;

/// A sidecar's generation plus its plaintext.
pub type SidecarContents = (u64, Zeroizing<Vec<u8>>);

/// What the vault knows about a sidecar file's generation (for the commit CAS).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Known {
    /// Not read or written in this session.
    Unknown,
    /// The file did not exist.
    Absent,
    /// The last generation read or written.
    Generation(u64),
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
    challenge: Option<(ChallengeId, [u8; CHALLENGE_WORDS])>,
    /// Last known generation of meta / journal.
    sidecar_generations: Cell<[Known; 2]>,
    kdf: KdfParams,
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

fn slot_dek(slot: Option<&Slot>) -> Result<&[u8; 32], VaultError> {
    slot.ok_or(VaultError::InvalidState)?
        .bytes()
        .first_chunk::<SLOT_DEK_END>()
        .ok_or(INTERNAL)
}

fn slot_passphrase(slot: Option<&Slot>) -> Result<Bip39Passphrase, VaultError> {
    let bytes = slot.ok_or(VaultError::InvalidState)?.bytes();
    if bytes.get(SLOT_FLAG).copied() != Some(1) {
        return Ok(Bip39Passphrase::empty());
    }
    let len_bytes = bytes
        .get(SLOT_PASSPHRASE_LEN..SLOT_PASSPHRASE)
        .ok_or(INTERNAL)?;
    let len = usize::from(u16::from_be_bytes(
        len_bytes.try_into().map_err(|_| INTERNAL)?,
    ));
    let end = SLOT_PASSPHRASE
        .checked_add(len)
        .filter(|end| *end <= SLOT_PASSPHRASE_END)
        .ok_or(INTERNAL)?;
    Ok(Bip39Passphrase::from_bytes(
        bytes.get(SLOT_PASSPHRASE..end).ok_or(INTERNAL)?,
    )?)
}

/// Clears the passphrase area and, if given, stores the passphrase.
fn set_slot_passphrase(
    slot: &mut dyn LockedSlot,
    passphrase: Option<&Bip39Passphrase>,
) -> Result<(), VaultError> {
    let bytes = slot.bytes_mut();
    bytes
        .get_mut(SLOT_FLAG..SLOT_LEN)
        .ok_or(INTERNAL)?
        .zeroize();
    if let Some(passphrase) = passphrase {
        let value = passphrase.as_bytes();
        let len = u16::try_from(value.len()).map_err(|_| INTERNAL)?;
        let end = SLOT_PASSPHRASE
            .checked_add(value.len())
            .filter(|end| *end <= SLOT_PASSPHRASE_END)
            .ok_or(INTERNAL)?;
        *bytes.get_mut(SLOT_FLAG).ok_or(INTERNAL)? = 1;
        bytes
            .get_mut(SLOT_PASSPHRASE_LEN..SLOT_PASSPHRASE)
            .ok_or(INTERNAL)?
            .copy_from_slice(&len.to_be_bytes());
        bytes
            .get_mut(SLOT_PASSPHRASE..end)
            .ok_or(INTERNAL)?
            .copy_from_slice(value);
    }
    Ok(())
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

const fn status_after_unlock(bip39: &Bip39Record) -> VaultStatus {
    if bip39.passphrase_used {
        VaultStatus::PassphraseRequired
    } else if bip39.backup_confirmed {
        VaultStatus::Unlocked {
            alt_passphrase: false,
        }
    } else {
        VaultStatus::BackupPending
    }
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
    let seed = mnemonic.to_seed(passphrase);
    Ok(evm_address_from_seed(ctx, &seed, AccountIndex::ZERO)?)
}

/// Optional lowercase `0x` + exactly 64 hex digits, value in [1, n−1] (spec/02 §8.2).
fn parse_private_key(text: &str) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    let mut key = Zeroizing::new([0_u8; 32]);
    hex::decode_into(digits.as_bytes(), key.as_mut(), true)
        .map_err(|_| KeyError::InvalidPrivateKey)?;
    let mut check = SecretKey::from_byte_array(*key).map_err(|_| KeyError::InvalidPrivateKey)?;
    check.non_secure_erase();
    Ok(key)
}

fn fresh_record_id(rng: &mut impl RandomSource, payload: &Payload) -> Result<[u8; 16], VaultError> {
    let id = random_nonzero_id_with(rng)?;
    let taken =
        payload.bip39.record_id == id || payload.raw_keys.iter().any(|raw| raw.record_id == id);
    if taken {
        return Err(KeyError::RandomnessUnavailable.into());
    }
    Ok(id)
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
        })
    }

    /// The current state.
    #[must_use]
    pub const fn status(&self) -> VaultStatus {
        self.status
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

    fn seed(&self, payload: &Payload) -> Result<Zeroizing<[u8; 64]>, VaultError> {
        Ok(payload
            .bip39
            .mnemonic
            .to_seed(&slot_passphrase(self.slot.as_ref())?))
    }

    fn secret_for(
        &self,
        ctx: &Secp256k1<All>,
        payload: &Payload,
        key: KeyRef,
    ) -> Result<SecretKey, VaultError> {
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
            KeyRef::Btc { coin, chain, index } => btc_path(coin, chain, index)?,
        };
        let seed = self.seed(payload)?;
        Ok(secret_key_from_seed(ctx, &seed, &path)?)
    }

    fn commit_vault(&mut self, expected: Option<u64>, bytes: Vec<u8>) -> Result<(), VaultError> {
        self.storage
            .commit(FileKind::Vault, expected, &bytes)
            .map_err(VaultError::Storage)?;
        self.ciphertext = Some(bytes);
        Ok(())
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
    ) -> Result<Zeroizing<String>, VaultError> {
        self.create_wallet_with_rng(&mut OsRandom, password, slot, now_unix)
    }

    pub(crate) fn create_wallet_with_rng(
        &mut self,
        rng: &mut impl RandomSource,
        password: &VaultPassword,
        slot: Slot,
        now_unix: u64,
    ) -> Result<Zeroizing<String>, VaultError> {
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
            let payload = Payload {
                bip39: Bip39Record {
                    record_id,
                    created_unix: now_unix,
                    mnemonic,
                    passphrase_used: false,
                    backup_confirmed: false,
                    passphrase_check: [0; 4],
                },
                raw_keys: Vec::new(),
            };
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
            Ok((bytes, dek, vault_id, payload.bip39.mnemonic.phrase()))
        })();
        let (bytes, dek, vault_id, phrase) = match sealed {
            Ok(values) => values,
            Err(error) => {
                wipe_and_drop(slot);
                return Err(error);
            }
        };
        if let Err(error) = self.storage.commit(FileKind::Vault, None, &bytes) {
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
            let payload = Payload {
                bip39: Bip39Record {
                    record_id,
                    created_unix: now_unix,
                    mnemonic,
                    passphrase_used: passphrase.is_some(),
                    backup_confirmed: true,
                    passphrase_check,
                },
                raw_keys: Vec::new(),
            };
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
        if let Err(error) = self.storage.commit(FileKind::Vault, None, &bytes) {
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
        let opened = (|| -> Result<_, VaultError> {
            let bytes = self
                .storage
                .load(FileKind::Vault)
                .map_err(VaultError::Storage)?
                .ok_or(VaultError::Storage(StorageError::NotFound))?;
            let (header, dek) = format::unwrap_dek(&bytes, password, &self.kdf)?;
            let payload = format::decrypt_payload(&bytes, &dek, &self.kdf)?;
            Ok((
                bytes,
                header.vault_id,
                dek,
                status_after_unlock(&payload.bip39),
            ))
        })();
        let (bytes, vault_id, dek, next) = match opened {
            Ok(values) => values,
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
                return Err(error);
            }
        };
        self.open_session(slot, &dek, None)?;
        self.ciphertext = Some(bytes);
        self.id = Some(vault_id);
        self.status = next;
        Ok(next)
    }

    /// Checks the BIP39 passphrase against the stored 4-byte value (spec/02 §7.5).
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
        let payload = self.payload()?;
        let ctx = secp_context(&mut OsRandom)?;
        let check = passphrase_check(&address_zero(&ctx, &payload.bip39.mnemonic, &passphrase)?);
        let matches = check
            .as_slice()
            .ct_eq(payload.bip39.passphrase_check.as_slice())
            .unwrap_u8()
            == 1;
        let slot = self.slot.as_mut().ok_or(VaultError::InvalidState)?;
        set_slot_passphrase(slot.as_mut(), Some(&passphrase))?;
        self.status = if matches {
            VaultStatus::Unlocked {
                alt_passphrase: false,
            }
        } else {
            VaultStatus::PassphraseMismatch
        };
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
        let slot = self.slot.as_mut().ok_or(VaultError::InvalidState)?;
        set_slot_passphrase(slot.as_mut(), None)?;
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
        self.status = VaultStatus::Unlocked {
            alt_passphrase: true,
        };
        Ok(self.status)
    }

    /// Wipes and releases the slot, drops the challenge and the held vault bytes (spec/02 §7.2).
    /// A no-op outside the session states.
    pub fn lock(&mut self) {
        if let Some(slot) = self.slot.take() {
            wipe_and_drop(slot);
        }
        self.challenge = None;
        self.ciphertext = None;
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
    /// # Errors
    ///
    /// `InvalidState` outside `Corrupt`/`MainMissing`, `Storage(NotFound)` without `.prev`, and
    /// the unlock errors of the `.prev` file.
    pub fn recover_from_prev(
        &mut self,
        password: &VaultPassword,
        slot: Slot,
        now_unix: u64,
    ) -> Result<VaultStatus, VaultError> {
        if !matches!(
            self.status,
            VaultStatus::Corrupt { .. } | VaultStatus::MainMissing
        ) {
            wipe_and_drop(slot);
            return Err(VaultError::InvalidState);
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
            }
            self.storage
                .commit(FileKind::Vault, None, &bytes)
                .map_err(VaultError::Storage)?;
            Ok((
                bytes,
                header.vault_id,
                dek,
                status_after_unlock(&payload.bip39),
            ))
        })();
        let (bytes, vault_id, dek, next) = match recovered {
            Ok(values) => values,
            Err(error) => {
                wipe_and_drop(slot);
                return Err(error);
            }
        };
        self.open_session(slot, &dek, None)?;
        self.ciphertext = Some(bytes);
        self.id = Some(vault_id);
        self.status = next;
        Ok(next)
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
        let words = self.payload()?.bip39.mnemonic.word_count().words();
        let mut candidates = [0_u8; 24];
        for (index, slot) in candidates.iter_mut().enumerate() {
            *slot = u8::try_from(index).map_err(|_| INTERNAL)?;
        }
        for offset in 0..CHALLENGE_WORDS {
            let remaining =
                u32::try_from(words.checked_sub(offset).ok_or(INTERNAL)?).map_err(|_| INTERNAL)?;
            let pick = usize::try_from(random_below_with(rng, remaining)?).map_err(|_| INTERNAL)?;
            candidates.swap(
                offset,
                offset
                    .checked_add(pick)
                    .filter(|index| *index < words)
                    .ok_or(INTERNAL)?,
            );
        }
        let mut positions = [0_u8; CHALLENGE_WORDS];
        for (position, candidate) in positions.iter_mut().zip(candidates) {
            *position = candidate.checked_add(1).ok_or(INTERNAL)?;
        }
        positions.sort_unstable();
        let id = ChallengeId(random_nonzero_id_with(rng)?);
        self.challenge = Some((id, positions));
        Ok(BackupChallenge { id, positions })
    }

    /// Verifies 4 words and the last 6 hex characters of the account-0 address (spec/02 §8.3).
    /// All 5 comparisons run in constant time and are decided once.
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`; `ChallengeStale` for an unknown id; `BackupMismatch`
    /// for wrong or malformed answers (the challenge is discarded); `Storage` if the commit fails.
    pub fn confirm_backup(
        &mut self,
        id: ChallengeId,
        words: [&str; 4],
        address_suffix: &str,
    ) -> Result<(), VaultError> {
        if self.status != VaultStatus::BackupPending {
            return Err(VaultError::InvalidState);
        }
        let positions = match self.challenge {
            Some((current, positions)) if current == id => positions,
            _ => return Err(VaultError::ChallengeStale),
        };
        self.challenge = None;
        let well_formed = words.iter().all(|word| {
            (1..=MAX_BACKUP_WORD).contains(&word.len())
                && word.bytes().all(|b| b.is_ascii_lowercase())
        }) && address_suffix.len() == ADDRESS_SUFFIX_LEN
            && address_suffix.bytes().all(|b| b.is_ascii_hexdigit());
        if !well_formed {
            return Err(VaultError::BackupMismatch);
        }
        let mut payload = self.payload()?;
        let mut all = Choice::from(1);
        for (position, answer) in positions.iter().zip(words) {
            let expected = payload.bip39.mnemonic.word_at(*position)?;
            all &= expected.as_bytes().ct_eq(answer.as_bytes());
        }
        let ctx = secp_context(&mut OsRandom)?;
        let address =
            address_zero(&ctx, &payload.bip39.mnemonic, &Bip39Passphrase::empty())?.to_lower_hex();
        let expected_suffix = address
            .get(address.len().saturating_sub(ADDRESS_SUFFIX_LEN)..)
            .ok_or(INTERNAL)?;
        let answer_suffix = address_suffix.to_ascii_lowercase();
        all &= expected_suffix.as_bytes().ct_eq(answer_suffix.as_bytes());
        if all.unwrap_u8() != 1 {
            return Err(VaultError::BackupMismatch);
        }
        payload.bip39.backup_confirmed = true;
        self.rewrite_payload(&payload)?;
        self.status = VaultStatus::Unlocked {
            alt_passphrase: false,
        };
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
        let key = parse_private_key(hex_key)?;
        let mut payload = self.payload()?;
        let duplicate = payload.raw_keys.iter().fold(0_u8, |seen, raw| {
            seen | raw.key.as_slice().ct_eq(key.as_slice()).unwrap_u8()
        });
        if duplicate != 0 {
            return Err(VaultError::DuplicateKey);
        }
        if payload.raw_keys.len() >= MAX_RAW_KEYS {
            return Err(VaultError::RecordLimit);
        }
        let record_id = fresh_record_id(&mut OsRandom, &payload)?;
        payload.raw_keys.push(RawKeyRecord {
            record_id,
            created_unix: now_unix,
            key,
        });
        self.rewrite_payload(&payload)?;
        Ok(RecordId(record_id))
    }

    /// Removes a raw key after re-entering the password. The BIP39 record cannot be removed.
    ///
    /// # Errors
    ///
    /// `BackupNotConfirmed`/`InvalidState`, `UnlockFailed`, `RecordNotFound` or `Storage`.
    pub fn remove_evm_raw_key(
        &mut self,
        password: &VaultPassword,
        id: RecordId,
    ) -> Result<(), VaultError> {
        self.require_signing()?;
        self.verify_password(password)?;
        let mut payload = self.payload()?;
        let before = payload.raw_keys.len();
        payload.raw_keys.retain(|raw| raw.record_id != id.0);
        if payload.raw_keys.len() == before {
            return Err(VaultError::RecordNotFound);
        }
        self.rewrite_payload(&payload)
    }

    /// `Rewrap` with the new password, then one more `PayloadRewrite` so `.prev` also uses the
    /// new password (spec/02 §4.4). The DEK is unchanged.
    ///
    /// # Errors
    ///
    /// `InvalidState`, `UnlockFailed` for a wrong old password, `OutOfMemory` or `Storage`.
    /// If the second commit fails the vault already uses the new password.
    pub fn change_password(
        &mut self,
        old: &VaultPassword,
        new: &VaultPassword,
    ) -> Result<(), VaultError> {
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
        self.rewrite_payload(&payload)
    }

    /// The mnemonic, after re-entering the password (spec/02 §9).
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`/`Unlocked`, or `UnlockFailed`.
    pub fn reveal_mnemonic(
        &self,
        password: &VaultPassword,
    ) -> Result<Zeroizing<String>, VaultError> {
        self.require_public()?;
        self.verify_password(password)?;
        Ok(self.payload()?.bip39.mnemonic.phrase())
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
    ) -> Result<Zeroizing<String>, VaultError> {
        self.require_signing()?;
        self.verify_password(password)?;
        let payload = self.payload()?;
        let ctx = secp_context(&mut OsRandom)?;
        let mut secret = self.secret_for(&ctx, &payload, KeyRef::Evm(src))?;
        let raw = Zeroizing::new(secret.secret_bytes());
        secret.non_secure_erase();
        let mut out = Zeroizing::new(String::with_capacity(64));
        hex::encode_into(raw.as_slice(), &mut out);
        Ok(out)
    }

    /// The address of one EVM key source.
    ///
    /// # Errors
    ///
    /// `InvalidState` outside `BackupPending`/`Unlocked`, `RecordNotFound`, or a derivation error.
    pub fn evm_address(&self, src: EvmKeySource) -> Result<Address, VaultError> {
        self.require_public()?;
        let payload = self.payload()?;
        let ctx = secp_context(&mut OsRandom)?;
        let mut secret = self.secret_for(&ctx, &payload, KeyRef::Evm(src))?;
        let public = PublicKey::from_secret_key(&ctx, &secret);
        secret.non_secure_erase();
        Ok(Address::from_public_key(&public))
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
        let payload = self.payload()?;
        let seed = self.seed(&payload)?;
        let ctx = secp_context(&mut OsRandom)?;
        indices
            .iter()
            .map(|index| evm_address_from_seed(&ctx, &seed, *index).map_err(VaultError::from))
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

    /// Opens `meta.ywm` or `journal.ywj`; `None` if the file does not exist.
    ///
    /// # Errors
    ///
    /// `InvalidState` (also for `FileKind::Vault`), `SidecarCorrupt`, `SidecarVaultMismatch`, `Storage`.
    pub fn open_sidecar(&self, kind: FileKind) -> Result<Option<SidecarContents>, VaultError> {
        self.require_public()?;
        let index = sidecar_index(kind)?;
        let vault_id = self.id.ok_or(VaultError::InvalidState)?;
        let opened = match self.storage.load(kind).map_err(VaultError::Storage)? {
            None => None,
            Some(bytes) => Some(format::open_sidecar(
                kind,
                &bytes,
                &vault_id,
                slot_dek(self.slot.as_ref())?,
            )?),
        };
        let mut known = self.sidecar_generations.get();
        if let Some(entry) = known.get_mut(index) {
            *entry = Known::from_option(opened.as_ref().map(|(generation, _)| *generation));
        }
        self.sidecar_generations.set(known);
        Ok(opened)
    }

    /// Seals and commits a sidecar with generation CAS against the last generation seen.
    /// Returns the new generation.
    ///
    /// # Errors
    ///
    /// `InvalidState` (also for `FileKind::Vault`), `Storage(GenerationConflict)` and other
    /// storage errors, `Storage(TooLarge)` above the plaintext bound.
    pub fn save_sidecar(&mut self, kind: FileKind, plaintext: &[u8]) -> Result<u64, VaultError> {
        self.require_public()?;
        let index = sidecar_index(kind)?;
        let vault_id = self.id.ok_or(VaultError::InvalidState)?;
        let mut known = self.sidecar_generations.get();
        let expected = match known.get(index).copied().unwrap_or(Known::Unknown) {
            Known::Generation(last) => Some(last),
            Known::Absent => None,
            Known::Unknown => self
                .storage
                .load(kind)
                .map_err(VaultError::Storage)?
                .map(|bytes| {
                    format::decode_sidecar_header(kind, &bytes).map(|header| header.generation)
                })
                .transpose()?,
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
        self.storage
            .commit(kind, expected, &bytes)
            .map_err(VaultError::Storage)?;
        if let Some(entry) = known.get_mut(index) {
            *entry = Known::Generation(generation);
        }
        self.sidecar_generations.set(known);
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
        let ctx = secp_context(&mut OsRandom)?;
        let mut secret = self.secret_for(&ctx, &payload, key)?;
        let result = f(&ctx, &secret);
        secret.non_secure_erase();
        result
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
