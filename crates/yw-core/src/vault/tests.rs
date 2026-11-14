//! vault v3 tests: golden G1–G5 (spec/09 §3.12), tamper table and codec rejections
//! (spec/02 §11.6, spec/09 §4.1 V-1–V-4), sidecars and storage contract (§11.7), state machine
//! and backup (§11.8), and the vault-level entropy cases of §11.1. Structure follows
//! `archive/spec-v2.4:crates/secret-core/src/vault.rs:1161-1432` with v3 values.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::format::{
    self, Bip39Record, CORRUPT_NEXT_SEAL, KDF_CALLS, MAX_RAW_KEYS, PAYLOAD_MAGIC, Payload,
    RawKeyRecord, SealMaterial, peek_generation_with,
};
use super::{
    EvmKeySource, FileKind, KDF_V3, KdfParams, KeyRef, LockedSlot, PasswordChange, RecordId,
    SLOT_LEN, Vault, VaultError, VaultStatus, VaultStorage, check_vault_header, peek_generation,
};
use crate::bip32::path::{AccountIndex, BtcChain, BtcCoin};
use crate::bip39::Mnemonic;
use crate::entropy::{FailingRandom, ScriptedRandom};
use crate::error::{KeyError, StorageError};
use crate::hex;
use crate::password::{Bip39Passphrase, VaultPassword};
use crate::secret::SecretString;

const KDF_TEST: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};
const ABOUT: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const GOLDEN_PASSWORD: &[u8] = b"correct horse battery staple";
/// Regression pin of OUR vault v3 byte format (spec/02 §11.6, spec/09 §3.12 G1), recorded once
/// from `print_golden_sha256` in the commit where G3 (independent decryption) passed. A change
/// means the format changed: bump `VAULT_VERSION` or revert. Not a protocol vector.
const GOLDEN_SHA256: &str = "cf7a45ce3702eae648d3909a598218cdab494d8d49dfd384f60d8c673f459c92";
const PASSWORD: &[u8] = b"test password 1";
const OTHER_PASSWORD: &[u8] = b"another password 2";

// ---------------------------------------------------------------- test doubles

#[derive(Default)]
struct Files {
    main: Option<Vec<u8>>,
    prev: Option<Vec<u8>>,
    quarantined: Vec<(u64, Vec<u8>)>,
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "independent fault switches of the test double"
)]
struct MemInner {
    vault: Files,
    meta: Files,
    journal: Files,
    commits: usize,
    params: KdfParams,
    fail_commits: bool,
    /// The commit lands, then reports `Io(6)` (a failed read-back after the replace).
    fail_after_write: bool,
    /// A crash after this many commits: later commits fail without landing (`Io(5)`). With
    /// `land_then_fail`, the commit at that count still lands but reports `Io(6)` first.
    fail_from: Option<usize>,
    land_then_fail: bool,
    /// `load(Vault)` fails with `Io(7)` (the read-back after a failed `Rewrap`).
    fail_vault_load: bool,
    /// `replace_copy` fails with `Io(5)` without writing.
    fail_copies: bool,
    copy_writes: usize,
}

impl MemInner {
    fn file(&mut self, kind: FileKind) -> &mut Files {
        match kind {
            FileKind::Vault => &mut self.vault,
            FileKind::Meta => &mut self.meta,
            FileKind::Journal => &mut self.journal,
        }
    }
}

/// In-memory `VaultStorage` with the spec/02 §6.2 commit contract; records commits.
#[derive(Clone)]
struct MemStorage(Arc<Mutex<MemInner>>);

impl MemStorage {
    fn new(params: KdfParams) -> Self {
        Self(Arc::new(Mutex::new(MemInner {
            vault: Files::default(),
            meta: Files::default(),
            journal: Files::default(),
            commits: 0,
            params,
            fail_commits: false,
            fail_after_write: false,
            fail_from: None,
            land_then_fail: false,
            fail_vault_load: false,
            fail_copies: false,
            copy_writes: 0,
        })))
    }

    fn with<T>(&self, f: impl FnOnce(&mut MemInner) -> T) -> T {
        f(&mut self.0.lock().unwrap())
    }

    fn commits(&self) -> usize {
        self.with(|inner| inner.commits)
    }

    fn main(&self, kind: FileKind) -> Option<Vec<u8>> {
        self.with(|inner| inner.file(kind).main.clone())
    }

    fn prev(&self, kind: FileKind) -> Option<Vec<u8>> {
        self.with(|inner| inner.file(kind).prev.clone())
    }

    fn set_main(&self, kind: FileKind, bytes: Option<Vec<u8>>) {
        self.with(|inner| inner.file(kind).main = bytes);
    }

    fn set_prev(&self, kind: FileKind, bytes: Option<Vec<u8>>) {
        self.with(|inner| inner.file(kind).prev = bytes);
    }

    fn quarantined(&self, kind: FileKind) -> Vec<(u64, Vec<u8>)> {
        self.with(|inner| inner.file(kind).quarantined.clone())
    }

    fn set_fail_commits(&self, fail: bool) {
        self.with(|inner| inner.fail_commits = fail);
    }

    fn set_fail_after_write(&self, fail: bool) {
        self.with(|inner| inner.fail_after_write = fail);
    }

    fn set_fail_vault_load(&self, fail: bool) {
        self.with(|inner| inner.fail_vault_load = fail);
    }

    fn set_fail_copies(&self, fail: bool) {
        self.with(|inner| inner.fail_copies = fail);
    }

    fn copy_writes(&self) -> usize {
        self.with(|inner| inner.copy_writes)
    }

    /// E-VLT-006 "격리하고 새로 시작": main and `.prev` move aside (`quarantined`) at `now`.
    fn set_aside(&self, kind: FileKind, now: u64) {
        self.with(|inner| {
            let file = inner.file(kind);
            let main = file.main.take();
            let prev = file.prev.take();
            file.quarantined
                .extend(main.into_iter().chain(prev).map(|bytes| (now, bytes)));
        });
    }

    fn set_fail_from(&self, from: Option<usize>, land_then_fail: bool) {
        self.with(|inner| {
            inner.fail_from = from;
            inner.land_then_fail = land_then_fail;
        });
    }
}

impl VaultStorage for MemStorage {
    fn load(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
        if kind == FileKind::Vault && self.with(|inner| inner.fail_vault_load) {
            return Err(StorageError::Io(7));
        }
        Ok(self.main(kind))
    }

    fn load_prev(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.prev(kind))
    }

    fn commit(
        &mut self,
        kind: FileKind,
        expected: Option<u64>,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        self.with(|inner| {
            let landed = inner.commits;
            let crashed = inner
                .fail_from
                .is_some_and(|from| landed > from || (landed == from && !inner.land_then_fail));
            if inner.fail_commits || crashed {
                return Err(StorageError::Io(5));
            }
            let params = inner.params;
            let file = inner.file(kind);
            match (expected, file.main.as_deref()) {
                (None, Some(_)) => return Err(StorageError::AlreadyExists),
                (Some(_), None) => return Err(StorageError::NotFound),
                (Some(generation), Some(main)) => match peek_generation_with(kind, main, &params) {
                    None => return Err(StorageError::Corrupt),
                    Some(found) if found != generation => {
                        return Err(StorageError::GenerationConflict);
                    }
                    Some(_) => {}
                },
                (None, None) => {}
            }
            if let Some(old) = file.main.take() {
                file.prev = Some(old);
            }
            file.main = Some(bytes.to_vec());
            inner.commits += 1;
            if inner.fail_after_write || (inner.land_then_fail && inner.fail_from == Some(landed)) {
                return Err(StorageError::Io(6));
            }
            Ok(())
        })
    }

    fn quarantine(&mut self, kind: FileKind, now_unix: u64) -> Result<(), StorageError> {
        self.with(|inner| {
            let file = inner.file(kind);
            let main = file.main.take().ok_or(StorageError::NotFound)?;
            file.quarantined.push((now_unix, main));
            Ok(())
        })
    }

    /// `q<i>` for each set-aside file, `prev` for a `.prev` without a main file.
    fn copies(&self, kind: FileKind) -> Result<Vec<String>, StorageError> {
        self.with(|inner| {
            let file = inner.file(kind);
            let mut names: Vec<String> = (0..file.quarantined.len())
                .map(|index| format!("q{index}"))
                .collect();
            if file.main.is_none() && file.prev.is_some() {
                names.push("prev".to_owned());
            }
            Ok(names)
        })
    }

    fn load_copy(&self, kind: FileKind, name: &str) -> Result<Option<Vec<u8>>, StorageError> {
        self.with(|inner| {
            let file = inner.file(kind);
            Ok(match name.strip_prefix('q') {
                Some(index) => file
                    .quarantined
                    .get(index.parse::<usize>().unwrap())
                    .map(|(_, bytes)| bytes.clone()),
                None => file.prev.clone(),
            })
        })
    }

    fn replace_copy(
        &mut self,
        kind: FileKind,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        self.with(|inner| {
            if inner.fail_copies {
                return Err(StorageError::Io(5));
            }
            inner.copy_writes += 1;
            let file = inner.file(kind);
            let slot = match name.strip_prefix('q') {
                Some(index) => {
                    &mut file
                        .quarantined
                        .get_mut(index.parse::<usize>().unwrap())
                        .unwrap()
                        .1
                }
                None => file.prev.as_mut().unwrap(),
            };
            *slot = bytes.to_vec();
            Ok(())
        })
    }
}

/// Heap slot that records at drop time whether the vault wiped it first.
struct HeapSlot {
    bytes: Box<[u8; SLOT_LEN]>,
    wiped_at_drop: Arc<AtomicBool>,
}

impl LockedSlot for HeapSlot {
    fn bytes(&self) -> &[u8; SLOT_LEN] {
        &self.bytes
    }

    fn bytes_mut(&mut self) -> &mut [u8; SLOT_LEN] {
        &mut self.bytes
    }
}

impl Drop for HeapSlot {
    fn drop(&mut self) {
        self.wiped_at_drop
            .store(self.bytes.iter().all(|byte| *byte == 0), Ordering::SeqCst);
    }
}

fn slot() -> (Box<dyn LockedSlot>, Arc<AtomicBool>) {
    let flag = Arc::new(AtomicBool::new(false));
    // Pre-filled with garbage so a missing wipe is visible.
    let slot = HeapSlot {
        bytes: Box::new([0xa5; SLOT_LEN]),
        wiped_at_drop: Arc::clone(&flag),
    };
    (Box::new(slot), flag)
}

fn new_slot() -> Box<dyn LockedSlot> {
    slot().0
}

fn pw(text: &[u8]) -> VaultPassword {
    VaultPassword::new(text).unwrap()
}

fn kdf_calls() -> u32 {
    KDF_CALLS.with(std::cell::Cell::get)
}

fn index(i: u32) -> AccountIndex {
    AccountIndex::new(i).unwrap()
}

fn flip(bytes: &mut [u8], offset: usize) {
    *bytes.get_mut(offset).unwrap() ^= 1;
}

fn put(bytes: &mut [u8], offset: usize, value: &[u8]) {
    bytes
        .get_mut(offset..offset + value.len())
        .unwrap()
        .copy_from_slice(value);
}

fn at(bytes: &[u8], range: core::ops::Range<usize>) -> &[u8] {
    bytes.get(range).unwrap()
}

fn seq<const N: usize>(start: u8) -> [u8; N] {
    let mut out = [0_u8; N];
    for (offset, byte) in out.iter_mut().enumerate() {
        *byte = start + u8::try_from(offset).unwrap();
    }
    out
}

fn empty_vault(params: KdfParams) -> (MemStorage, Vault) {
    let storage = MemStorage::new(params);
    let vault = Vault::load_with_params(Box::new(storage.clone()), params).unwrap();
    (storage, vault)
}

fn imported(passphrase: Option<&str>) -> (MemStorage, Vault) {
    let (storage, mut vault) = empty_vault(KDF_TEST);
    let passphrase = passphrase.map(|value| Bip39Passphrase::new(value).unwrap());
    vault
        .import_mnemonic(&pw(PASSWORD), ABOUT, passphrase, new_slot(), 1_790_000_000)
        .unwrap();
    (storage, vault)
}

fn created() -> (MemStorage, Vault, SecretString) {
    let (storage, mut vault) = empty_vault(KDF_TEST);
    let phrase = vault
        .create_wallet(&pw(PASSWORD), new_slot(), 1_790_000_000)
        .unwrap();
    (storage, vault, phrase)
}

/// The `change_password` check that reads every sidecar (core does not parse them).
fn any_sidecar(_: FileKind, _: &[u8]) -> bool {
    true
}

fn reload(storage: &MemStorage) -> Vault {
    Vault::load_with_params(Box::new(storage.clone()), KDF_TEST).unwrap()
}

fn golden_payload() -> Payload {
    Payload::new(Some(Bip39Record {
        record_id: seq(0x90),
        created_unix: 1_790_000_000,
        mnemonic: Mnemonic::from_entropy(&[0; 32]).unwrap(),
        passphrase_used: false,
        backup_confirmed: false,
        passphrase_check: [0; 4],
    }))
}

fn seal_fixed(params: &KdfParams) -> Vec<u8> {
    let password = pw(GOLDEN_PASSWORD);
    let dek: [u8; 32] = seq(0x20);
    let payload = golden_payload();
    let material = SealMaterial {
        password: &password,
        vault_id: seq(0x00),
        dek: &dek,
        kdf_salt: seq(0x40),
        wrap_nonce: seq(0x50),
        payload_nonce: seq(0x70),
        generation: 1,
        payload: &payload,
    };
    format::seal_create_with(&material, params).unwrap()
}

/// Steps 1–9 with the test KDF; returns the payload's first raw key count to prove decoding.
fn open_all(bytes: &[u8], password: &[u8], params: &KdfParams) -> Result<usize, VaultError> {
    let (_, dek) = format::unwrap_dek(bytes, &pw(password), params)?;
    Ok(format::decrypt_payload(bytes, &dek, params)?.raw_keys.len())
}

// ---------------------------------------------------------------- §11.1 entropy (vault level)

#[test]
fn create_draws_entropy_first() {
    let (storage, mut vault) = empty_vault(KDF_TEST);
    let script: Vec<u8> = (0x00..=0x1f).collect();
    let mut rng = ScriptedRandom::new(&script);
    let phrase = vault
        .create_wallet_with_rng(&mut rng, &pw(PASSWORD), new_slot(), 1)
        .unwrap();
    assert_eq!(
        phrase.expose(),
        Mnemonic::from_entropy(&script)
            .unwrap()
            .phrase()
            .unwrap()
            .expose()
    );
    assert_eq!(storage.commits(), 1);
    assert_eq!(vault.status(), VaultStatus::BackupPending);
}

#[test]
fn rng_failure_aborts_without_commit() {
    let (storage, mut vault) = empty_vault(KDF_TEST);
    let (slot, wiped) = slot();
    let error = vault
        .create_wallet_with_rng(&mut FailingRandom, &pw(PASSWORD), slot, 1)
        .unwrap_err();
    assert_eq!(error, VaultError::Key(KeyError::RandomnessUnavailable));
    assert_eq!(storage.commits(), 0);
    assert_eq!(vault.status(), VaultStatus::NoVault);
    assert!(wiped.load(Ordering::SeqCst));
    // Stuck entropy (all bytes equal) is also fatal and commits nothing.
    let mut stuck = ScriptedRandom::new(&[0x5a; 32]);
    let error = vault
        .create_wallet_with_rng(&mut stuck, &pw(PASSWORD), new_slot(), 1)
        .unwrap_err();
    assert_eq!(error, VaultError::Key(KeyError::RandomnessUnavailable));
    assert_eq!(storage.commits(), 0);
    let error = vault
        .import_mnemonic_with_rng(
            &mut FailingRandom,
            &pw(PASSWORD),
            ABOUT,
            None,
            new_slot(),
            1,
        )
        .unwrap_err();
    assert_eq!(error, VaultError::Key(KeyError::RandomnessUnavailable));
    assert_eq!(storage.commits(), 0);
    assert_eq!(vault.status(), VaultStatus::NoVault);
}

// ---------------------------------------------------------------- §3.12 golden (production KDF)

#[test]
fn g1_g2_golden_bytes_and_field_offsets() {
    let bytes = seal_fixed(&KDF_V3);
    assert_eq!(bytes.len(), 272);
    assert_eq!(hex::encode(&Sha256::digest(&bytes)), GOLDEN_SHA256);
    assert_eq!(at(&bytes, 0..8), b"YWVLT003");
    assert_eq!(at(&bytes, 8..10), 3_u16.to_be_bytes());
    assert_eq!(at(&bytes, 10..12), 176_u16.to_be_bytes());
    assert_eq!(at(&bytes, 12..28), seq::<16>(0x00));
    assert_eq!(at(&bytes, 28..30), 1_u16.to_be_bytes());
    assert_eq!(at(&bytes, 30..34), 262_144_u32.to_be_bytes());
    assert_eq!(at(&bytes, 34..38), 3_u32.to_be_bytes());
    assert_eq!(at(&bytes, 38..42), 4_u32.to_be_bytes());
    assert_eq!(at(&bytes, 42..58), seq::<16>(0x40));
    assert_eq!(at(&bytes, 58..82), seq::<24>(0x50));
    assert_eq!(at(&bytes, 130..138), 1_u64.to_be_bytes());
    assert_eq!(at(&bytes, 138..162), seq::<24>(0x70));
    assert_eq!(at(&bytes, 162..166), 96_u32.to_be_bytes());
    assert_eq!(at(&bytes, 166..176), [0; 10]);
    assert_eq!(check_vault_header(&bytes), Ok(1));
    assert_eq!(peek_generation(FileKind::Vault, &bytes), Some(1));
}

#[test]
#[ignore = "prints the G1 digest once; run with --ignored --exact"]
#[expect(clippy::print_stdout, reason = "golden")]
fn print_golden_sha256() {
    println!("{}", hex::encode(&Sha256::digest(seal_fixed(&KDF_V3))));
}

#[test]
fn g3_independent_decryption() {
    let bytes = seal_fixed(&KDF_V3);
    // Everything below uses the primitives directly, not the vault module (spec/09 §3.12 G3).
    let field = |range: core::ops::Range<usize>| at(&bytes, range).to_vec();
    let m_kib = u32::from_be_bytes(field(30..34).try_into().unwrap());
    let t = u32::from_be_bytes(field(34..38).try_into().unwrap());
    let p = u32::from_be_bytes(field(38..42).try_into().unwrap());
    let params = Params::new(m_kib, t, p, Some(32)).unwrap();
    let mut blocks = vec![Block::default(); params.block_count()];
    let mut pw_kek = [0_u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(GOLDEN_PASSWORD, &field(42..58), &mut pw_kek, &mut blocks)
        .unwrap();
    let mut kek = [0_u8; 32];
    Hkdf::<Sha256>::new(Some(b"your-wallet/v3/kdf"), &pw_kek)
        .expand(b"your-wallet/v3/kek", &mut kek)
        .unwrap();
    let wrap = XChaCha20Poly1305::new_from_slice(&kek).unwrap();
    let dek = wrap
        .decrypt(
            XNonce::from_slice(&field(58..82)),
            AeadPayload {
                msg: &field(82..130),
                aad: &field(0..82),
            },
        )
        .unwrap();
    assert_eq!(dek, seq::<32>(0x20));
    let content = XChaCha20Poly1305::new_from_slice(&dek).unwrap();
    let plaintext = content
        .decrypt(
            XNonce::from_slice(&field(138..162)),
            AeadPayload {
                msg: &field(176..272),
                aad: &field(0..176),
            },
        )
        .unwrap();
    assert_eq!(plaintext.len(), 80);
    assert_eq!(plaintext.get(0..8).unwrap(), PAYLOAD_MAGIC);
    assert_eq!(plaintext.get(8..10).unwrap(), 1_u16.to_be_bytes());
    assert_eq!(plaintext.get(16..17).unwrap(), [1]);
    assert_eq!(plaintext.get(17..33).unwrap(), seq::<16>(0x90));
    assert_eq!(
        plaintext.get(33..41).unwrap(),
        1_790_000_000_u64.to_be_bytes()
    );
    assert_eq!(plaintext.get(41..42).unwrap(), [32]);
    assert_eq!(plaintext.get(42..74).unwrap(), [0; 32]);
    assert_eq!(plaintext.get(74..80).unwrap(), [0; 6]);
}

#[test]
fn g4_public_unlock_reaches_backup_pending_with_acc3() {
    let storage = MemStorage::new(KDF_V3);
    storage.set_main(FileKind::Vault, Some(seal_fixed(&KDF_V3)));
    let mut vault = Vault::load(Box::new(storage)).unwrap();
    assert_eq!(vault.status(), VaultStatus::Locked);
    assert_eq!(vault.vault_id(), Some(seq(0x00)));
    assert_eq!(
        vault.unlock(&pw(GOLDEN_PASSWORD), new_slot()),
        Ok(VaultStatus::BackupPending)
    );
    let address = vault.evm_address(EvmKeySource::Derived(index(0))).unwrap();
    assert_eq!(
        address.to_checksum(),
        "0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb"
    );
}

#[test]
fn g5_wrong_password_unlock_failed() {
    let storage = MemStorage::new(KDF_V3);
    storage.set_main(FileKind::Vault, Some(seal_fixed(&KDF_V3)));
    let mut vault = Vault::load(Box::new(storage)).unwrap();
    let (slot, wiped) = slot();
    assert_eq!(
        vault.unlock(&pw(b"correct horse battery stapler"), slot),
        Err(VaultError::UnlockFailed)
    );
    assert_eq!(vault.status(), VaultStatus::Locked);
    assert!(wiped.load(Ordering::SeqCst));
}

// ---------------------------------------------------------------- §11.6 tamper table (KDF_TEST)

enum Tamper {
    Flip(usize),
    Put(usize, Vec<u8>),
}

fn tampered(original: &[u8], tamper: &Tamper) -> Vec<u8> {
    let mut bytes = original.to_vec();
    match tamper {
        Tamper::Flip(offset) => flip(&mut bytes, *offset),
        Tamper::Put(offset, value) => put(&mut bytes, *offset, value),
    }
    bytes
}

#[test]
fn v1_header_tamper_table() {
    use Tamper::{Flip, Put};
    use VaultError::{
        Malformed, PayloadCorrupt, UnlockFailed, UnsupportedParams, UnsupportedVersion,
    };
    let original = seal_fixed(&KDF_TEST);
    assert_eq!(open_all(&original, GOLDEN_PASSWORD, &KDF_TEST), Ok(0));
    let be = |value: u32| value.to_be_bytes().to_vec();
    let table: Vec<(Tamper, VaultError, bool, &str)> = vec![
        (Flip(0), Malformed, false, "magic"),
        (Flip(11), Malformed, false, "header_len"),
        (Flip(166), Malformed, false, "flags"),
        (Flip(169), Malformed, false, "flags"),
        (Flip(170), Malformed, false, "reserved"),
        (Flip(175), Malformed, false, "reserved"),
        (Put(12, vec![0; 16]), Malformed, false, "vault_id zero"),
        (Put(130, vec![0; 8]), Malformed, false, "generation zero"),
        (Flip(165), Malformed, false, "payload_ct_len"),
        (Flip(162), Malformed, false, "payload_ct_len high"),
        (Flip(9), UnsupportedVersion, false, "version"),
        (Flip(29), UnsupportedParams, false, "kdf_id"),
        (Put(30, be(63)), UnsupportedParams, false, "m 63"),
        (Put(30, be(65)), UnsupportedParams, false, "m 65"),
        (Put(34, be(0)), UnsupportedParams, false, "t 0"),
        (Put(34, be(2)), UnsupportedParams, false, "t 2"),
        (Put(38, be(0)), UnsupportedParams, false, "p 0"),
        (Put(38, be(2)), UnsupportedParams, false, "p 2"),
        (
            Put(30, be(262_144)),
            UnsupportedParams,
            false,
            "m production",
        ),
        (Flip(12), UnlockFailed, true, "vault_id"),
        (Flip(27), UnlockFailed, true, "vault_id"),
        (Flip(42), UnlockFailed, true, "kdf_salt"),
        (Flip(57), UnlockFailed, true, "kdf_salt"),
        (Flip(58), UnlockFailed, true, "wrap_nonce"),
        (Flip(81), UnlockFailed, true, "wrap_nonce"),
        (Flip(82), UnlockFailed, true, "wrapped_dek"),
        (Flip(129), UnlockFailed, true, "wrapped_dek"),
        (Flip(136), PayloadCorrupt, true, "generation"),
        (Flip(130), PayloadCorrupt, true, "generation high"),
        (Flip(138), PayloadCorrupt, true, "payload_nonce"),
        (Flip(161), PayloadCorrupt, true, "payload_nonce"),
        (Flip(176), PayloadCorrupt, true, "payload_ct"),
        (Flip(230), PayloadCorrupt, true, "payload_ct"),
        (Flip(271), PayloadCorrupt, true, "tag"),
    ];
    for (tamper, expected, kdf_runs, label) in table {
        let bytes = tampered(&original, &tamper);
        let before = kdf_calls();
        assert_eq!(
            open_all(&bytes, GOLDEN_PASSWORD, &KDF_TEST),
            Err(expected),
            "{label}"
        );
        assert_eq!(kdf_calls() - before, u32::from(kdf_runs), "{label} KDF");
    }
}

#[test]
fn v1_truncation_and_extension_rejected_before_kdf() {
    let original = seal_fixed(&KDF_TEST);
    let before = kdf_calls();
    for len in 0..original.len() {
        let truncated = original.get(..len).unwrap();
        assert_eq!(
            open_all(truncated, GOLDEN_PASSWORD, &KDF_TEST),
            Err(VaultError::Malformed),
            "len {len}"
        );
    }
    let mut extended = original.clone();
    extended.push(0);
    assert_eq!(
        open_all(&extended, GOLDEN_PASSWORD, &KDF_TEST),
        Err(VaultError::Malformed)
    );
    assert_eq!(kdf_calls(), before);
}

#[test]
fn v2_wrong_password_and_wrapped_dek_tamper_are_identical() {
    let original = seal_fixed(&KDF_TEST);
    let wrong = open_all(&original, b"wrong password!!", &KDF_TEST).unwrap_err();
    let mut tampered = original.clone();
    flip(&mut tampered, 100);
    let tamper = open_all(&tampered, GOLDEN_PASSWORD, &KDF_TEST).unwrap_err();
    assert_eq!(wrong, VaultError::UnlockFailed);
    assert_eq!(wrong, tamper);
    assert_eq!(wrong.to_string(), tamper.to_string());
    assert_eq!(
        wrong.to_string(),
        "비밀번호가 올바르지 않거나 vault 파일이 손상되었습니다."
    );
}

#[test]
fn v3_test_kdf_file_is_unsupported_through_the_public_api() {
    let bytes = seal_fixed(&KDF_TEST);
    let before = kdf_calls();
    assert_eq!(
        check_vault_header(&bytes),
        Err(VaultError::UnsupportedParams)
    );
    assert_eq!(peek_generation(FileKind::Vault, &bytes), None);
    let storage = MemStorage::new(KDF_V3);
    storage.set_main(FileKind::Vault, Some(bytes));
    let vault = Vault::load(Box::new(storage)).unwrap();
    assert_eq!(
        vault.status(),
        VaultStatus::Corrupt {
            prev_available: false
        }
    );
    assert_eq!(kdf_calls(), before);
}

// ---------------------------------------------------------------- §4.6 payload codec

fn raw_record(byte: u8) -> RawKeyRecord {
    RawKeyRecord {
        record_id: [byte; 16],
        created_unix: 7,
        key: Zeroizing::new([byte; 32]),
    }
}

fn payload_bytes(records: &[Vec<u8>], count: u16) -> Vec<u8> {
    let mut out = PAYLOAD_MAGIC.to_vec();
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&[0; 6]);
    for record in records {
        out.extend_from_slice(record);
    }
    out
}

fn bip39_record(id: u8, entropy_len: u8, flags: u8, backup: u8, check: [u8; 4]) -> Vec<u8> {
    let mut out = vec![1];
    out.extend_from_slice(&[id; 16]);
    out.extend_from_slice(&5_u64.to_be_bytes());
    out.push(entropy_len);
    out.extend(std::iter::repeat_n(0x11, usize::from(entropy_len)));
    out.push(flags);
    out.push(backup);
    out.extend_from_slice(&check);
    out
}

fn raw_bytes(id: u8, key: [u8; 32]) -> Vec<u8> {
    let mut out = vec![2];
    out.extend_from_slice(&[id; 16]);
    out.extend_from_slice(&6_u64.to_be_bytes());
    out.extend_from_slice(&key);
    out
}

#[test]
fn payload_codec_rejection_table() {
    let good = bip39_record(1, 16, 0, 1, [0; 4]);
    let good_raw = raw_bytes(2, [3; 32]);
    assert!(Payload::decode(&payload_bytes(&[good.clone(), good_raw.clone()], 2)).is_ok());
    let order: [u8; 32] =
        hex::decode_array("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .unwrap();
    let mut bad_magic = payload_bytes(std::slice::from_ref(&good), 1);
    flip(&mut bad_magic, 0);
    let mut bad_reserved = payload_bytes(std::slice::from_ref(&good), 1);
    flip(&mut bad_reserved, 12);
    let mut trailing = payload_bytes(std::slice::from_ref(&good), 1);
    trailing.push(0);
    let mut truncated = payload_bytes(std::slice::from_ref(&good), 1);
    truncated.pop();
    let mut unknown_tag = good_raw.clone();
    put(&mut unknown_tag, 0, &[5]);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("magic", bad_magic),
        ("count 0", payload_bytes(&[], 0)),
        ("count 17", payload_bytes(std::slice::from_ref(&good), 17)),
        ("reserved", bad_reserved),
        (
            "unknown tag",
            payload_bytes(&[good.clone(), unknown_tag], 2),
        ),
        (
            "raw first",
            payload_bytes(&[good_raw.clone(), good.clone()], 2),
        ),
        (
            "record_id zero",
            payload_bytes(&[bip39_record(0, 16, 0, 1, [0; 4])], 1),
        ),
        (
            "record_id duplicate",
            payload_bytes(&[good.clone(), raw_bytes(1, [3; 32])], 2),
        ),
        (
            "entropy_len 17",
            payload_bytes(&[bip39_record(1, 17, 0, 1, [0; 4])], 1),
        ),
        (
            "entropy_len 0",
            payload_bytes(&[bip39_record(1, 0, 0, 1, [0; 4])], 1),
        ),
        (
            "flags reserved bit",
            payload_bytes(&[bip39_record(1, 16, 2, 1, [0; 4])], 1),
        ),
        (
            "check without passphrase",
            payload_bytes(&[bip39_record(1, 16, 0, 1, [0, 0, 0, 1])], 1),
        ),
        (
            "backup 2",
            payload_bytes(&[bip39_record(1, 16, 0, 2, [0; 4])], 1),
        ),
        (
            "pending with passphrase",
            payload_bytes(&[bip39_record(1, 16, 1, 0, [1; 4])], 1),
        ),
        (
            "raw key zero",
            payload_bytes(&[good.clone(), raw_bytes(2, [0; 32])], 2),
        ),
        (
            "raw key n",
            payload_bytes(&[good.clone(), raw_bytes(2, order)], 2),
        ),
        (
            "raw key duplicate",
            payload_bytes(
                &[good.clone(), raw_bytes(2, [3; 32]), raw_bytes(4, [3; 32])],
                3,
            ),
        ),
        (
            "count beyond records",
            payload_bytes(std::slice::from_ref(&good), 2),
        ),
        ("trailing", trailing),
        ("truncated", truncated),
    ];
    for (label, bytes) in cases {
        assert_eq!(
            Payload::decode(&bytes).err(),
            Some(VaultError::UnsupportedPayload),
            "{label}"
        );
    }
    // passphrase wallet (confirmed) with a check value decodes.
    assert!(Payload::decode(&payload_bytes(&[bip39_record(1, 32, 1, 1, [9; 4])], 1)).is_ok());
}

#[test]
fn sixteen_records_round_trip_and_seventeen_rejected() {
    let mut payload = golden_payload();
    payload.raw_keys.extend((1..=15).map(raw_record));
    let encoded = payload.encode().unwrap();
    let decoded = Payload::decode(&encoded).unwrap();
    assert_eq!(decoded.raw_keys.len(), 15);
    assert_eq!(decoded.encode().unwrap().as_slice(), encoded.as_slice());
    payload.raw_keys.push(raw_record(16));
    assert_eq!(payload.encode().err(), Some(VaultError::RecordLimit));
    let mut seventeen = encoded.to_vec();
    put(&mut seventeen, 8, &17_u16.to_be_bytes());
    seventeen.extend_from_slice(&raw_bytes(16, [16; 32]));
    assert_eq!(
        Payload::decode(&seventeen).err(),
        Some(VaultError::UnsupportedPayload)
    );
}

// ---------------------------------------------------------------- writes

#[test]
fn payload_rewrite_keeps_key_section_and_runs_no_kdf() {
    let (storage, mut vault) = imported(None);
    let before_bytes = storage.main(FileKind::Vault).unwrap();
    let before_kdf = kdf_calls();
    let mut key = [0_u8; 32];
    put(&mut key, 31, &[1]);
    let id = vault.import_evm_private_key(&hex::encode(&key), 9).unwrap();
    assert_eq!(kdf_calls(), before_kdf);
    let after = storage.main(FileKind::Vault).unwrap();
    assert_eq!(at(&after, 0..130), at(&before_bytes, 0..130));
    assert_eq!(
        peek_generation_with(FileKind::Vault, &after, &KDF_TEST),
        Some(2)
    );
    assert_ne!(at(&after, 138..162), at(&before_bytes, 138..162));
    assert_eq!(storage.prev(FileKind::Vault), Some(before_bytes));
    assert_eq!(vault.held_bytes(), Some(after.as_slice()));
    let raw = vault.raw_keys().unwrap();
    assert_eq!(raw.len(), 1);
    assert_eq!(raw.first().unwrap().0, id);
    assert_eq!(
        raw.first().unwrap().1.to_checksum(),
        "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
    );
    assert_eq!(
        vault
            .evm_address(EvmKeySource::Raw(id))
            .unwrap()
            .to_checksum(),
        "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
    );
}

// ---------------------------------------------------------------- DEK rotation (spec/02 §4.4)

const NEW_PASSWORD: &[u8] = b"new password 33";
const META_1: &[u8] = b"{\"schema\":\"yw-meta/3\"}";
/// Not meta JSON: a newer build's document (`SidecarUnsupported` in yw-app) must survive the
/// rotation byte for byte.
const META_2: &[u8] = b"\x00newer meta format\xff";
const JOURNAL_1: &[u8] = b"journal one";
const JOURNAL_2: &[u8] = b"journal two";
/// Commits of a complete change with both sidecars present: `Rewrap`, `PayloadRewrite`, meta ×2,
/// journal ×2, two rewrites without `PrevDek`.
const ROTATION_COMMITS: usize = 8;
const ROTATION_PASSPHRASE: &str = "TREZOR";

/// An imported wallet with one raw key and two saves of each sidecar (so every `.prev` exists).
fn rotation_wallet() -> (MemStorage, Vault) {
    rotation_wallet_with(None, true)
}

/// [`rotation_wallet`] with a BIP39 passphrase and/or without a journal.
fn rotation_wallet_with(passphrase: Option<&str>, journal: bool) -> (MemStorage, Vault) {
    let (storage, mut vault) = imported(passphrase);
    vault.import_evm_private_key(&"07".repeat(32), 2).unwrap();
    vault.save_sidecar(FileKind::Meta, META_1).unwrap();
    vault.save_sidecar(FileKind::Meta, META_2).unwrap();
    if journal {
        vault.save_sidecar(FileKind::Journal, JOURNAL_1).unwrap();
        vault.save_sidecar(FileKind::Journal, JOURNAL_2).unwrap();
    }
    (storage, vault)
}

fn held_dek(vault: &Vault) -> [u8; 32] {
    *vault.slot_bytes().unwrap().first_chunk::<32>().unwrap()
}

/// Every file in the folder (main, `.prev`, quarantined) with its kind.
fn disk_files(storage: &MemStorage) -> Vec<(FileKind, Vec<u8>)> {
    let mut out = Vec::new();
    for kind in [FileKind::Vault, FileKind::Meta, FileKind::Journal] {
        out.extend(storage.main(kind).map(|bytes| (kind, bytes)));
        out.extend(storage.prev(kind).map(|bytes| (kind, bytes)));
        out.extend(
            storage
                .quarantined(kind)
                .into_iter()
                .map(|(_, bytes)| (kind, bytes)),
        );
    }
    out
}

/// The encoded payloads of `vault.ywv` and its `.prev` under `dek`.
fn payload_encodings(storage: &MemStorage, dek: &[u8; 32]) -> Vec<Vec<u8>> {
    [storage.main(FileKind::Vault), storage.prev(FileKind::Vault)]
        .into_iter()
        .flatten()
        .filter_map(|bytes| format::decrypt_payload(&bytes, dek, &KDF_TEST).ok())
        .map(|payload| payload.encode().unwrap().to_vec())
        .collect()
}

/// What someone holding an old copy and the OLD password reaches in the folder right now: every
/// vault file the old password opens unwraps the OLD DEK (never the new one) and holds one of the
/// payloads from before the change; every file the OLD DEK opens holds content from before the
/// change.
fn assert_old_password_reach(
    storage: &MemStorage,
    vault_id: &[u8; 16],
    old_dek: &[u8; 32],
    before: &[Vec<u8>],
    label: &str,
) {
    for (kind, bytes) in disk_files(storage) {
        if kind == FileKind::Vault {
            if let Ok((_, dek)) = format::unwrap_dek(&bytes, &pw(PASSWORD), &KDF_TEST) {
                assert_eq!(
                    *dek, *old_dek,
                    "{label}: the old password unwraps the new DEK"
                );
            }
            if let Ok(payload) = format::decrypt_payload(&bytes, old_dek, &KDF_TEST) {
                assert!(payload.prev_dek.is_none(), "{label}");
                let encoded = payload.encode().unwrap().to_vec();
                assert!(before.contains(&encoded), "{label}: new vault content");
            }
        } else if let Ok((_, plain)) = format::open_sidecar(kind, &bytes, vault_id, old_dek) {
            assert!(
                [META_1, META_2, JOURNAL_1, JOURNAL_2].contains(&plain.as_slice()),
                "{label}: new {kind:?} content under the old DEK"
            );
        }
    }
}

/// Nothing in the folder (set-aside copies included) opens with `old_password` or under
/// `old_dek`.
fn assert_old_key_opens_nothing(
    storage: &MemStorage,
    vault_id: &[u8; 16],
    old_password: &[u8],
    old_dek: &[u8; 32],
    label: &str,
) {
    for (kind, bytes) in disk_files(storage) {
        if kind == FileKind::Vault {
            assert_eq!(
                format::unwrap_dek(&bytes, &pw(old_password), &KDF_TEST).err(),
                Some(VaultError::UnlockFailed),
                "{label}"
            );
            assert!(
                format::decrypt_payload(&bytes, old_dek, &KDF_TEST).is_err(),
                "{label}"
            );
        } else {
            assert!(
                format::open_sidecar(kind, &bytes, vault_id, old_dek).is_err(),
                "{label}: {kind:?} still under the old DEK"
            );
        }
    }
}

/// The rotation is finished: `vault.ywv` and its `.prev` unwrap the session DEK with
/// `password` and carry no `PrevDek`; meta, journal and their `.prev` (those that exist) open
/// under it.
fn assert_rotated(storage: &MemStorage, vault: &Vault, password: &[u8], label: &str) {
    let dek = held_dek(vault);
    let vault_id = vault.vault_id().unwrap();
    for bytes in [storage.main(FileKind::Vault), storage.prev(FileKind::Vault)] {
        let bytes = bytes.unwrap();
        let (_, unwrapped) = format::unwrap_dek(&bytes, &pw(password), &KDF_TEST).unwrap();
        assert_eq!(*unwrapped, dek, "{label}");
        let payload = format::decrypt_payload(&bytes, &dek, &KDF_TEST).unwrap();
        assert!(payload.prev_dek.is_none(), "{label}: PrevDek left behind");
    }
    for kind in [FileKind::Meta, FileKind::Journal] {
        for bytes in [storage.main(kind), storage.prev(kind)]
            .into_iter()
            .flatten()
        {
            assert!(
                format::open_sidecar(kind, &bytes, &vault_id, &dek).is_ok(),
                "{label}: {kind:?}"
            );
        }
    }
}

fn sidecar_text(vault: &Vault, kind: FileKind, prev: bool) -> Vec<u8> {
    let opened = if prev {
        vault.open_sidecar_prev(kind)
    } else {
        vault.open_sidecar(kind)
    };
    opened.unwrap().unwrap().1.expose().to_vec()
}

/// The wallet after a finished rotation: the raw key, and both sidecars with the content from
/// before the change in the main file and in `.prev` (each re-sealed copy of the main file).
fn assert_wallet_contents(vault: &Vault, label: &str) {
    assert_wallet_contents_with(vault, true, label);
}

/// [`assert_wallet_contents`] for a wallet with or without a journal.
fn assert_wallet_contents_with(vault: &Vault, journal: bool, label: &str) {
    assert_eq!(vault.raw_keys().unwrap().len(), 1, "{label}");
    assert_eq!(
        sidecar_text(vault, FileKind::Meta, false),
        META_2,
        "{label}"
    );
    assert_eq!(sidecar_text(vault, FileKind::Meta, true), META_2, "{label}");
    if !journal {
        assert!(
            vault.open_sidecar(FileKind::Journal).unwrap().is_none(),
            "{label}"
        );
        return;
    }
    assert_eq!(
        sidecar_text(vault, FileKind::Journal, false),
        JOURNAL_2,
        "{label}"
    );
    assert_eq!(
        sidecar_text(vault, FileKind::Journal, true),
        JOURNAL_2,
        "{label}"
    );
}

#[test]
fn change_password_rotates_dek() {
    let (storage, mut vault) = rotation_wallet();
    let old_dek = held_dek(&vault);
    let vault_id = vault.vault_id().unwrap();
    let old_copy = storage.main(FileKind::Vault).unwrap();
    let generation = peek_generation_with(FileKind::Vault, &old_copy, &KDF_TEST).unwrap();
    let commits = storage.commits();
    assert_eq!(
        vault.change_password(&pw(OTHER_PASSWORD), &pw(NEW_PASSWORD), &any_sidecar),
        Err(VaultError::UnlockFailed)
    );
    assert_eq!(storage.commits(), commits);

    let calls = kdf_calls();
    assert_eq!(
        vault.change_password(&pw(PASSWORD), &pw(NEW_PASSWORD), &any_sidecar),
        Ok(PasswordChange::Complete)
    );
    // Verify the old password + derive the new KEK: the rotation itself needs no Argon2.
    assert_eq!(kdf_calls() - calls, 2);
    assert_eq!(storage.commits(), commits + ROTATION_COMMITS);
    let new_dek = held_dek(&vault);
    assert_ne!(new_dek, old_dek);
    let main = storage.main(FileKind::Vault).unwrap();
    assert_eq!(
        peek_generation_with(FileKind::Vault, &main, &KDF_TEST),
        Some(generation + 4)
    );
    assert_rotated(&storage, &vault, NEW_PASSWORD, "complete");
    assert_old_key_opens_nothing(&storage, &vault_id, PASSWORD, &old_dek, "complete");
    // The old copy still opens with the old password, but its DEK opens nothing current.
    let (_, copy_dek) = format::unwrap_dek(&old_copy, &pw(PASSWORD), &KDF_TEST).unwrap();
    assert_eq!(*copy_dek, old_dek);
    assert_eq!(
        format::decrypt_payload(&main, &copy_dek, &KDF_TEST).err(),
        Some(VaultError::PayloadCorrupt)
    );
    // Sidecar plaintext moved byte for byte (META_2 is no meta JSON); generations went on.
    assert_wallet_contents(&vault, "complete");
    assert_eq!(
        vault.open_sidecar(FileKind::Meta).unwrap().unwrap().0,
        4,
        "two saves + two re-seals"
    );

    // Content added after the change is out of reach of the old copy.
    vault.import_evm_private_key(&"08".repeat(32), 3).unwrap();
    assert_eq!(vault.save_sidecar(FileKind::Meta, b"meta after"), Ok(5));
    assert_old_key_opens_nothing(&storage, &vault_id, PASSWORD, &old_dek, "added");

    vault.lock();
    assert_eq!(
        vault.unlock(&pw(PASSWORD), new_slot()),
        Err(VaultError::UnlockFailed)
    );
    assert_eq!(
        vault.unlock(&pw(NEW_PASSWORD), new_slot()),
        Ok(VaultStatus::Unlocked {
            alt_passphrase: false
        })
    );
    assert_eq!(held_dek(&vault), new_dek);
    assert_eq!(vault.raw_keys().unwrap().len(), 2);
    assert_eq!(sidecar_text(&vault, FileKind::Meta, false), b"meta after");
}

/// A crash (every later commit fails, then the process restarts) after each commit of the
/// change, and the same where that commit lands but reports a failure. The old password reaches
/// only content from before the change at every point; once the `Rewrap` landed, the new
/// password opens the wallet, the unlock finishes the rotation, and nothing is lost. Three
/// wallets: both sidecars; a BIP39 passphrase (the unlock stops at `PassphraseRequired`, and the
/// rotation is already finished there, spec/02 §4.4 "passphrase 입력 전 포함"); meta without a
/// journal (6 commits).
#[test]
fn dek_rotation_survives_a_crash_after_every_commit() {
    let setups = [
        (None, true, ROTATION_COMMITS),
        (Some(ROTATION_PASSPHRASE), true, ROTATION_COMMITS),
        (None, false, ROTATION_COMMITS - 2),
    ];
    for (passphrase, journal, commits) in setups {
        for land_then_fail in [false, true] {
            for k in 0..=commits {
                let landed = k + usize::from(land_then_fail);
                if landed > commits {
                    continue;
                }
                let label = format!(
                    "crash after {landed} (land_then_fail {land_then_fail}, passphrase {},                      journal {journal})",
                    passphrase.is_some()
                );
                crash_case(passphrase, journal, commits, k, land_then_fail, &label);
            }
        }
    }
}

/// One point of [`dek_rotation_survives_a_crash_after_every_commit`].
fn crash_case(
    passphrase: Option<&str>,
    journal: bool,
    commits: usize,
    k: usize,
    land_then_fail: bool,
    label: &str,
) {
    let landed = k + usize::from(land_then_fail);
    let (storage, mut vault) = rotation_wallet_with(passphrase, journal);
    let old_dek = held_dek(&vault);
    let vault_id = vault.vault_id().unwrap();
    let before = payload_encodings(&storage, &old_dek);
    let base = storage.commits();
    storage.set_fail_from(Some(base + k), land_then_fail);
    let expected = if landed == 0 {
        Err(VaultError::Storage(StorageError::Io(5)))
    } else if landed == commits {
        Ok(PasswordChange::Complete)
    } else {
        Ok(PasswordChange::PrevNotRefreshed)
    };
    assert_eq!(
        vault.change_password(&pw(PASSWORD), &pw(NEW_PASSWORD), &any_sidecar),
        expected,
        "{label}"
    );
    assert_eq!(storage.commits(), base + landed, "{label}");
    drop(vault);
    storage.set_fail_from(None, false);
    assert_old_password_reach(&storage, &vault_id, &old_dek, &before, label);

    let unlocked = Ok(if passphrase.is_some() {
        VaultStatus::PassphraseRequired
    } else {
        VaultStatus::Unlocked {
            alt_passphrase: false,
        }
    });
    let enter = |vault: &mut Vault| {
        if let Some(text) = passphrase {
            assert_eq!(
                vault.enter_passphrase(Bip39Passphrase::new(text).unwrap()),
                Ok(VaultStatus::Unlocked {
                    alt_passphrase: false
                }),
                "{label}"
            );
        }
    };
    let mut vault = reload(&storage);
    if landed == 0 {
        assert_eq!(
            vault.unlock(&pw(NEW_PASSWORD), new_slot()),
            Err(VaultError::UnlockFailed),
            "{label}"
        );
        assert_eq!(vault.unlock(&pw(PASSWORD), new_slot()), unlocked, "{label}");
        assert_eq!(held_dek(&vault), old_dek, "{label}");
        enter(&mut vault);
        assert_eq!(sidecar_text(&vault, FileKind::Meta, true), META_1);
        if journal {
            assert_eq!(sidecar_text(&vault, FileKind::Journal, true), JOURNAL_1);
        }
        return;
    }
    assert_eq!(
        vault.unlock(&pw(PASSWORD), new_slot()),
        Err(VaultError::UnlockFailed),
        "{label}"
    );
    assert_eq!(
        vault.unlock(&pw(NEW_PASSWORD), new_slot()),
        unlocked,
        "{label}"
    );
    // Finished by the unlock itself, before any passphrase is entered.
    assert_rotated(&storage, &vault, NEW_PASSWORD, label);
    assert_old_key_opens_nothing(&storage, &vault_id, PASSWORD, &old_dek, label);
    enter(&mut vault);
    assert_wallet_contents_with(&vault, journal, label);
    vault.import_evm_private_key(&"08".repeat(32), 3).unwrap();
    vault.save_sidecar(FileKind::Meta, b"meta after").unwrap();
    assert_old_key_opens_nothing(&storage, &vault_id, PASSWORD, &old_dek, label);
}

/// Only the `Rewrap` landed: a sidecar save may not seal under the new DEK while
/// `vault.ywv.prev` is still the old-password file, so it refuses while writes keep failing (both
/// sidecars still open, the journal under the old DEK); once writes work, the save finishes the
/// rotation first.
#[test]
fn sidecar_save_finishes_the_rotation_and_never_runs_ahead_of_vault_prev() {
    let (storage, mut vault) = rotation_wallet();
    let old_dek = held_dek(&vault);
    let vault_id = vault.vault_id().unwrap();
    storage.set_fail_from(Some(storage.commits() + 1), false);
    assert_eq!(
        vault.change_password(&pw(PASSWORD), &pw(NEW_PASSWORD), &any_sidecar),
        Ok(PasswordChange::PrevNotRefreshed)
    );
    let meta = storage.main(FileKind::Meta);
    assert_eq!(
        vault.save_sidecar(FileKind::Meta, b"meta 3"),
        Err(VaultError::Storage(StorageError::Io(5)))
    );
    assert_eq!(storage.main(FileKind::Meta), meta);
    assert_eq!(sidecar_text(&vault, FileKind::Journal, false), JOURNAL_2);
    assert_eq!(sidecar_text(&vault, FileKind::Meta, true), META_1);

    storage.set_fail_from(None, false);
    // Two saves + two re-seals + this save.
    assert_eq!(vault.save_sidecar(FileKind::Meta, b"meta 3"), Ok(5));
    assert_rotated(&storage, &vault, NEW_PASSWORD, "save");
    assert_old_key_opens_nothing(&storage, &vault_id, PASSWORD, &old_dek, "save");
    assert_eq!(sidecar_text(&vault, FileKind::Meta, false), b"meta 3");
    assert_eq!(sidecar_text(&vault, FileKind::Meta, true), META_2);
    assert_eq!(sidecar_text(&vault, FileKind::Journal, true), JOURNAL_2);
}

/// A damaged `vault.ywv` during an unfinished rotation: while `vault.ywv.prev` is still the file
/// from before the change, only the old password restores it (and the untouched old-DEK sidecars
/// fit it); once it holds the new DEK and `PrevDek`, the new password restores it and the
/// rotation finishes.
#[test]
fn prev_recovery_inside_the_rotation_window() {
    for landed in [1_usize, 2, 4, 6] {
        let label = format!("crash after {landed}");
        let (storage, mut vault) = rotation_wallet();
        let old_dek = held_dek(&vault);
        let vault_id = vault.vault_id().unwrap();
        storage.set_fail_from(Some(storage.commits() + landed), false);
        assert_eq!(
            vault.change_password(&pw(PASSWORD), &pw(NEW_PASSWORD), &any_sidecar),
            Ok(PasswordChange::PrevNotRefreshed),
            "{label}"
        );
        drop(vault);
        storage.set_fail_from(None, false);
        let mut damaged = storage.main(FileKind::Vault).unwrap();
        *damaged.last_mut().unwrap() ^= 1;
        storage.set_main(FileKind::Vault, Some(damaged));
        let mut vault = reload(&storage);
        assert_eq!(
            vault.unlock(&pw(NEW_PASSWORD), new_slot()),
            Err(VaultError::PayloadCorrupt),
            "{label}"
        );
        if landed == 1 {
            assert_eq!(
                vault.recover_from_prev(&pw(NEW_PASSWORD), new_slot(), 9),
                Err(VaultError::UnlockFailed),
                "{label}"
            );
            vault
                .recover_from_prev(&pw(PASSWORD), new_slot(), 9)
                .unwrap();
            assert_eq!(held_dek(&vault), old_dek, "{label}");
            assert_eq!(sidecar_text(&vault, FileKind::Meta, false), META_2);
            assert_eq!(sidecar_text(&vault, FileKind::Journal, true), JOURNAL_1);
            continue;
        }
        vault
            .recover_from_prev(&pw(NEW_PASSWORD), new_slot(), 9)
            .unwrap();
        assert_eq!(vault.quarantined_at(), Some(9), "{label}");
        assert_rotated(&storage, &vault, NEW_PASSWORD, &label);
        assert_old_key_opens_nothing(&storage, &vault_id, PASSWORD, &old_dek, &label);
        assert_wallet_contents(&vault, &label);
    }
}

/// A sidecar that does not open refuses the change before anything is written (its old-DEK
/// `.prev` is the E-VLT-006 choice (a)); after the file is restored the change goes through.
#[test]
fn change_password_refuses_while_a_sidecar_does_not_open() {
    let (storage, mut vault) = rotation_wallet();
    let journal = storage.main(FileKind::Journal).unwrap();
    let mut damaged = journal.clone();
    *damaged.last_mut().unwrap() ^= 1;
    storage.set_main(FileKind::Journal, Some(damaged));
    let files = disk_files(&storage);
    let commits = storage.commits();
    assert_eq!(
        vault.change_password(&pw(PASSWORD), &pw(NEW_PASSWORD), &any_sidecar),
        Err(VaultError::SidecarCorrupt(FileKind::Journal))
    );
    assert_eq!(storage.commits(), commits);
    assert_eq!(disk_files(&storage), files);

    // A meta file of another vault refuses the same way.
    storage.set_main(FileKind::Journal, Some(journal));
    let foreign = format::seal_sidecar(
        FileKind::Meta,
        &seq(0x60),
        3,
        &seq(0x10),
        &held_dek(&vault),
        META_1,
    )
    .unwrap();
    let meta = storage.main(FileKind::Meta);
    storage.set_main(FileKind::Meta, Some(foreign));
    assert_eq!(
        vault.change_password(&pw(PASSWORD), &pw(NEW_PASSWORD), &any_sidecar),
        Err(VaultError::SidecarVaultMismatch(FileKind::Meta))
    );
    assert_eq!(storage.commits(), commits);
    vault.lock();
    vault.unlock(&pw(PASSWORD), new_slot()).unwrap();

    storage.set_main(FileKind::Meta, meta);
    assert_eq!(
        vault.change_password(&pw(PASSWORD), &pw(NEW_PASSWORD), &any_sidecar),
        Ok(PasswordChange::Complete)
    );
    assert_wallet_contents(&vault, "restored");
}

/// A second change while the first one is unfinished finishes the first rotation, then rotates
/// again: neither earlier key opens anything afterwards.
#[test]
fn second_change_finishes_the_unfinished_rotation_first() {
    let (storage, mut vault) = rotation_wallet();
    let first = held_dek(&vault);
    let vault_id = vault.vault_id().unwrap();
    storage.set_fail_from(Some(storage.commits() + 3), false);
    assert_eq!(
        vault.change_password(&pw(PASSWORD), &pw(NEW_PASSWORD), &any_sidecar),
        Ok(PasswordChange::PrevNotRefreshed)
    );
    storage.set_fail_from(None, false);
    let second = held_dek(&vault);
    assert_eq!(
        vault.change_password(&pw(NEW_PASSWORD), &pw(b"third password 3"), &any_sidecar),
        Ok(PasswordChange::Complete)
    );
    let third = held_dek(&vault);
    assert!(first != second && second != third && first != third);
    assert_rotated(&storage, &vault, b"third password 3", "third");
    assert_old_key_opens_nothing(&storage, &vault_id, PASSWORD, &first, "first");
    assert_old_key_opens_nothing(&storage, &vault_id, NEW_PASSWORD, &second, "second");
    assert_wallet_contents(&vault, "third");
}

/// A sidecar that opens but that the caller cannot read (yw-app: `SidecarUnsupported`, a newer
/// build's format) refuses the change before anything is written: rotating would commit it twice
/// and push out the older `.prev` this build can still read (the E-VLT-006 `.prev` choice).
#[test]
fn change_password_refuses_a_sidecar_the_caller_cannot_read() {
    let (storage, mut vault) = rotation_wallet();
    let files = disk_files(&storage);
    let commits = storage.commits();
    let json_meta =
        |kind: FileKind, plain: &[u8]| kind != FileKind::Meta || plain.starts_with(b"{");
    assert_eq!(
        vault.change_password(&pw(PASSWORD), &pw(NEW_PASSWORD), &json_meta),
        Err(VaultError::SidecarUnsupported(FileKind::Meta))
    );
    let journal_one =
        |kind: FileKind, plain: &[u8]| kind != FileKind::Journal || plain == JOURNAL_1;
    assert_eq!(
        vault.change_password(&pw(PASSWORD), &pw(NEW_PASSWORD), &journal_one),
        Err(VaultError::SidecarUnsupported(FileKind::Journal))
    );
    // A wrong old password is still reported first.
    assert_eq!(
        vault.change_password(&pw(OTHER_PASSWORD), &pw(NEW_PASSWORD), &json_meta),
        Err(VaultError::UnlockFailed)
    );
    assert_eq!(storage.commits(), commits);
    assert_eq!(disk_files(&storage), files);
    // The readable older copy is still there for the `.prev` choice.
    assert_eq!(sidecar_text(&vault, FileKind::Meta, true), META_1);
    assert_eq!(
        vault.change_password(&pw(PASSWORD), &pw(NEW_PASSWORD), &any_sidecar),
        Ok(PasswordChange::Complete)
    );
}

/// The `Rewrap` write reports a failure and `vault.ywv` cannot be read back: whether the change
/// landed is unknown, so the session locks (nothing is sealed under either DEK) and the result
/// is `Unconfirmed`, not "the old password still works". Landed: only the new password opens
/// and its unlock finishes the rotation. Not landed: the old password opens everything as before.
#[test]
fn rewrap_with_an_unknown_outcome_locks_the_session() {
    for landed in [true, false] {
        let label = format!("landed {landed}");
        let (storage, mut vault) = rotation_wallet();
        let old_dek = held_dek(&vault);
        let vault_id = vault.vault_id().unwrap();
        let base = storage.commits();
        storage.set_fail_vault_load(true);
        if landed {
            storage.set_fail_after_write(true);
        } else {
            storage.set_fail_commits(true);
        }
        assert_eq!(
            vault.change_password(&pw(PASSWORD), &pw(NEW_PASSWORD), &any_sidecar),
            Ok(PasswordChange::Unconfirmed),
            "{label}"
        );
        assert_eq!(vault.status(), VaultStatus::Locked, "{label}");
        assert!(vault.slot_bytes().is_none(), "{label}");
        assert_eq!(
            vault.save_sidecar(FileKind::Journal, b"after"),
            Err(VaultError::InvalidState),
            "{label}"
        );
        assert_eq!(storage.commits(), base + usize::from(landed), "{label}");
        storage.set_fail_vault_load(false);
        storage.set_fail_after_write(false);
        storage.set_fail_commits(false);
        let unlocked = Ok(VaultStatus::Unlocked {
            alt_passphrase: false,
        });
        if landed {
            assert_eq!(
                vault.unlock(&pw(PASSWORD), new_slot()),
                Err(VaultError::UnlockFailed),
                "{label}"
            );
            assert_eq!(
                vault.unlock(&pw(NEW_PASSWORD), new_slot()),
                unlocked,
                "{label}"
            );
            assert_rotated(&storage, &vault, NEW_PASSWORD, &label);
            assert_old_key_opens_nothing(&storage, &vault_id, PASSWORD, &old_dek, &label);
            assert_wallet_contents(&vault, &label);
        } else {
            assert_eq!(
                vault.unlock(&pw(NEW_PASSWORD), new_slot()),
                Err(VaultError::UnlockFailed),
                "{label}"
            );
            assert_eq!(vault.unlock(&pw(PASSWORD), new_slot()), unlocked, "{label}");
            assert_eq!(held_dek(&vault), old_dek, "{label}");
            assert_eq!(sidecar_text(&vault, FileKind::Meta, true), META_1);
            assert_eq!(sidecar_text(&vault, FileKind::Journal, true), JOURNAL_1);
        }
    }
}

/// The copies E-VLT-006 set aside for restoring by hand (`*.corrupt-*`, `*.prev.corrupt-*`) and
/// a `.prev` without a main file are re-sealed under the new DEK (same generation and bytes), so
/// a copy put back after the change still opens; a damaged copy is left as it is. A failed copy
/// write keeps `PrevDek`, and the next unlock finishes it.
#[test]
fn set_aside_sidecar_copies_follow_the_rotation() {
    for fail_copies in [false, true] {
        let label = format!("fail_copies {fail_copies}");
        let (storage, mut vault) = rotation_wallet();
        let old_dek = held_dek(&vault);
        let vault_id = vault.vault_id().unwrap();
        let before = payload_encodings(&storage, &old_dek);
        // Journal "격리하고 새로 시작": JOURNAL_2 and its `.prev` JOURNAL_1 move aside, and the
        // fresh journal is saved (with JOURNAL_1 again, content the reach check knows).
        storage.set_aside(FileKind::Journal, 5);
        assert!(vault.open_sidecar(FileKind::Journal).unwrap().is_none());
        assert_eq!(vault.save_sidecar(FileKind::Journal, JOURNAL_1), Ok(1));
        // A damaged set-aside meta, and no meta.ywm, so its `.prev` (META_1) is left alone.
        let mut damaged = storage.main(FileKind::Meta).unwrap();
        *damaged.last_mut().unwrap() ^= 1;
        storage.with(|inner| inner.meta.quarantined.push((6, damaged.clone())));
        storage.set_main(FileKind::Meta, None);
        assert!(vault.open_sidecar(FileKind::Meta).unwrap().is_none());
        let base = storage.commits();
        storage.set_fail_copies(fail_copies);
        assert_eq!(
            vault.change_password(&pw(PASSWORD), &pw(NEW_PASSWORD), &any_sidecar),
            Ok(if fail_copies {
                PasswordChange::PrevNotRefreshed
            } else {
                PasswordChange::Complete
            }),
            "{label}"
        );
        if fail_copies {
            // Rewrap, PayloadRewrite, journal ×2; `PrevDek` stays.
            assert_eq!(storage.commits(), base + 4, "{label}");
            assert_eq!(storage.copy_writes(), 0, "{label}");
            assert!(vault.payload().unwrap().prev_dek.is_some(), "{label}");
            drop(vault);
            storage.set_fail_copies(false);
            assert_old_password_reach(&storage, &vault_id, &old_dek, &before, &label);
            vault = reload(&storage);
            assert_eq!(
                vault.unlock(&pw(NEW_PASSWORD), new_slot()),
                Ok(VaultStatus::Unlocked {
                    alt_passphrase: false
                }),
                "{label}"
            );
        } else {
            // Rewrap, PayloadRewrite, journal ×2 (meta has no main file), two rewrites.
            assert_eq!(storage.commits(), base + 6, "{label}");
        }
        // The two set-aside journals and meta's lone `.prev`; the damaged meta is skipped.
        assert_eq!(storage.copy_writes(), 3, "{label}");
        assert!(vault.payload().unwrap().prev_dek.is_none(), "{label}");
        assert_rotated(&storage, &vault, NEW_PASSWORD, &label);
        assert_old_key_opens_nothing(&storage, &vault_id, PASSWORD, &old_dek, &label);
        let dek = held_dek(&vault);
        let journals: Vec<(u64, Vec<u8>)> = storage
            .quarantined(FileKind::Journal)
            .iter()
            .map(|(_, bytes)| {
                let (generation, plain) =
                    format::open_sidecar(FileKind::Journal, bytes, &vault_id, &dek).unwrap();
                (generation, plain.to_vec())
            })
            .collect();
        assert_eq!(
            journals,
            [(2, JOURNAL_2.to_vec()), (1, JOURNAL_1.to_vec())],
            "{label}"
        );
        assert_eq!(
            storage.quarantined(FileKind::Meta),
            [(6, damaged)],
            "{label}"
        );
        assert_eq!(
            sidecar_text(&vault, FileKind::Meta, true),
            META_1,
            "{label}"
        );

        // Put back by hand (recovery guide): the old journal opens with the new key.
        vault.lock();
        let (_, set_aside) = storage.quarantined(FileKind::Journal).swap_remove(0);
        storage.set_main(FileKind::Journal, Some(set_aside));
        vault.unlock(&pw(NEW_PASSWORD), new_slot()).unwrap();
        assert_eq!(sidecar_text(&vault, FileKind::Journal, false), JOURNAL_2);
        assert_eq!(vault.save_sidecar(FileKind::Journal, b"journal 3"), Ok(3));
    }
}

/// A sidecar damaged while the rotation is pending (V1 and V2 landed, then a crash): the unlock
/// re-seals meta but keeps `PrevDek` for the journal, whose `.prev` still opens under it; the
/// E-VLT-006 `.prev` choice puts that old-DEK copy back, and the next save finishes the rotation.
#[test]
fn a_sidecar_damaged_inside_the_rotation_window() {
    let (storage, mut vault) = rotation_wallet();
    let old_dek = held_dek(&vault);
    let vault_id = vault.vault_id().unwrap();
    storage.set_fail_from(Some(storage.commits() + 2), false);
    assert_eq!(
        vault.change_password(&pw(PASSWORD), &pw(NEW_PASSWORD), &any_sidecar),
        Ok(PasswordChange::PrevNotRefreshed)
    );
    drop(vault);
    storage.set_fail_from(None, false);
    let mut damaged = storage.main(FileKind::Journal).unwrap();
    *damaged.last_mut().unwrap() ^= 1;
    storage.set_main(FileKind::Journal, Some(damaged));

    let mut vault = reload(&storage);
    assert_eq!(
        vault.unlock(&pw(NEW_PASSWORD), new_slot()),
        Ok(VaultStatus::Unlocked {
            alt_passphrase: false
        })
    );
    assert!(vault.payload().unwrap().prev_dek.is_some());
    let new_dek = held_dek(&vault);
    let meta = storage.main(FileKind::Meta).unwrap();
    assert!(format::open_sidecar(FileKind::Meta, &meta, &vault_id, &new_dek).is_ok());
    assert_eq!(
        vault
            .open_sidecar(FileKind::Journal)
            .map(|opened| opened.is_some()),
        Err(VaultError::SidecarCorrupt(FileKind::Journal))
    );
    assert_eq!(sidecar_text(&vault, FileKind::Journal, true), JOURNAL_1);
    assert_eq!(
        vault.save_sidecar(FileKind::Journal, b"journal 3"),
        Err(VaultError::SidecarCorrupt(FileKind::Journal))
    );
    // Meta saves go on (the rotation is past V2).
    assert!(vault.save_sidecar(FileKind::Meta, META_2).is_ok());

    // yw-app's `restore_prev`: the damaged file aside, the `.prev` bytes in its place.
    let prev = storage.prev(FileKind::Journal).unwrap();
    VaultStorage::quarantine(&mut storage.clone(), FileKind::Journal, 9).unwrap();
    storage.set_main(FileKind::Journal, Some(prev));
    assert_eq!(sidecar_text(&vault, FileKind::Journal, false), JOURNAL_1);
    assert!(vault.save_sidecar(FileKind::Journal, b"journal 3").is_ok());
    assert!(vault.payload().unwrap().prev_dek.is_none());
    assert_rotated(&storage, &vault, NEW_PASSWORD, "restored");
    assert_old_key_opens_nothing(&storage, &vault_id, PASSWORD, &old_dek, "restored");
    assert_eq!(sidecar_text(&vault, FileKind::Journal, false), b"journal 3");
    assert_eq!(sidecar_text(&vault, FileKind::Journal, true), JOURNAL_1);
}

/// The `PrevDek` block (tag 7, spec/02 §4.6): after the records, not counted, exactly one, a
/// non-constant key different from the DEK in use.
#[test]
fn prev_dek_block_codec() {
    let mut payload = golden_payload();
    let base = payload.encode().unwrap().to_vec();
    payload.prev_dek = Some(Zeroizing::new(seq(0x30)));
    let encoded = payload.encode().unwrap().to_vec();
    let mut expected = base.clone();
    expected.push(7);
    expected.extend_from_slice(&seq::<32>(0x30));
    assert_eq!(encoded, expected);
    assert_eq!(at(&encoded, 8..10), at(&base, 8..10), "record_count");
    let decoded = Payload::decode(&encoded).unwrap();
    assert_eq!(decoded.prev_dek.as_deref(), Some(&seq::<32>(0x30)));
    assert_eq!(decoded.encode().unwrap().as_slice(), encoded.as_slice());
    // A build before the block sees bytes after the records: the "trailing" rejection.
    let block = |tag: u8, key: &[u8]| {
        let mut out = base.clone();
        out.push(tag);
        out.extend_from_slice(key);
        out
    };
    let mut twice = encoded.clone();
    twice.extend_from_slice(at(&encoded, base.len()..encoded.len()));
    let mut extra = encoded.clone();
    extra.push(0);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("all zero", block(7, &[0; 32])),
        ("all one value", block(7, &[0x55; 32])),
        ("tag 8", block(8, &seq::<32>(0x30))),
        ("short", block(7, &seq::<31>(0x30))),
        ("twice", twice),
        ("trailing byte", extra),
        ("tag only", block(7, &[])),
    ];
    for (label, bytes) in cases {
        assert_eq!(
            Payload::decode(&bytes).err(),
            Some(VaultError::UnsupportedPayload),
            "{label}"
        );
    }
    // A previous DEK equal to the DEK in use is refused after authentication.
    let password = pw(PASSWORD);
    let dek: [u8; 32] = seq(0x30);
    let material = SealMaterial {
        password: &password,
        vault_id: seq(0x01),
        dek: &dek,
        kdf_salt: seq(0x40),
        wrap_nonce: seq(0x50),
        payload_nonce: seq(0x70),
        generation: 1,
        payload: &payload,
    };
    let sealed = format::seal_create_with(&material, &KDF_TEST).unwrap();
    assert_eq!(
        open_all(&sealed, PASSWORD, &KDF_TEST),
        Err(VaultError::UnsupportedPayload)
    );
    payload.prev_dek = Some(Zeroizing::new(seq(0x20)));
    let material = SealMaterial {
        password: &password,
        vault_id: seq(0x01),
        dek: &dek,
        kdf_salt: seq(0x40),
        wrap_nonce: seq(0x50),
        payload_nonce: seq(0x70),
        generation: 1,
        payload: &payload,
    };
    let sealed = format::seal_create_with(&material, &KDF_TEST).unwrap();
    assert_eq!(open_all(&sealed, PASSWORD, &KDF_TEST), Ok(0));
}

#[test]
fn self_check_failure_commits_nothing() {
    let (storage, mut vault) = empty_vault(KDF_TEST);
    CORRUPT_NEXT_SEAL.with(|flag| flag.set(true));
    let (slot, wiped) = slot();
    let error = vault.create_wallet(&pw(PASSWORD), slot, 1).unwrap_err();
    assert_eq!(error, VaultError::Key(KeyError::Internal));
    assert_eq!(storage.commits(), 0);
    assert_eq!(vault.status(), VaultStatus::NoVault);
    assert!(wiped.load(Ordering::SeqCst));

    let (storage, mut vault) = imported(None);
    let commits = storage.commits();
    CORRUPT_NEXT_SEAL.with(|flag| flag.set(true));
    assert_eq!(
        vault.import_evm_private_key(&"07".repeat(32), 1),
        Err(VaultError::Key(KeyError::Internal))
    );
    assert_eq!(storage.commits(), commits);
    assert!(vault.raw_keys().unwrap().is_empty());
}

#[test]
fn storage_failure_keeps_state() {
    let (storage, mut vault) = empty_vault(KDF_TEST);
    storage.set_fail_commits(true);
    let (slot, wiped) = slot();
    assert_eq!(
        vault.create_wallet(&pw(PASSWORD), slot, 1).unwrap_err(),
        VaultError::Storage(StorageError::Io(5))
    );
    assert_eq!(vault.status(), VaultStatus::NoVault);
    assert!(wiped.load(Ordering::SeqCst));
    storage.set_fail_commits(false);
    let (storage, mut vault) = imported(None);
    storage.set_fail_commits(true);
    assert_eq!(
        vault.change_password(&pw(PASSWORD), &pw(b"new password 33"), &any_sidecar),
        Err(VaultError::Storage(StorageError::Io(5)))
    );
    storage.set_fail_commits(false);
    vault.lock();
    assert_eq!(
        vault.unlock(&pw(PASSWORD), new_slot()),
        Ok(VaultStatus::Unlocked {
            alt_passphrase: false
        })
    );
}

// ---------------------------------------------------------------- §11.7 sidecars and storage

#[test]
fn v4_sidecar_round_trip_mismatch_tamper_and_cas() {
    let (storage, mut vault) = imported(None);
    assert_eq!(
        vault.open_sidecar(FileKind::Meta).unwrap().map(|(g, _)| g),
        None
    );
    assert_eq!(vault.save_sidecar(FileKind::Meta, b"meta-1").unwrap(), 1);
    assert_eq!(vault.save_sidecar(FileKind::Meta, b"meta-2").unwrap(), 2);
    assert_eq!(
        vault.save_sidecar(FileKind::Journal, b"journal").unwrap(),
        1
    );
    let (generation, plaintext) = vault.open_sidecar(FileKind::Meta).unwrap().unwrap();
    assert_eq!((generation, plaintext.expose()), (2, b"meta-2".as_slice()));
    let meta = storage.main(FileKind::Meta).unwrap();
    let journal = storage.main(FileKind::Journal).unwrap();
    assert_eq!(peek_generation(FileKind::Meta, &meta), Some(2));
    assert_eq!(peek_generation(FileKind::Journal, &meta), None);

    // Magic cross: meta bytes presented as the journal.
    storage.set_main(FileKind::Journal, Some(meta.clone()));
    assert_eq!(
        vault.open_sidecar(FileKind::Journal).err(),
        Some(VaultError::SidecarCorrupt(FileKind::Journal))
    );
    storage.set_main(FileKind::Journal, Some(journal));

    // One bit anywhere: header structure, AAD, ciphertext or tag.
    for offset in [0, 20, 40, 63, 64, meta.len() - 1] {
        let mut tampered = meta.clone();
        flip(&mut tampered, offset);
        storage.set_main(FileKind::Meta, Some(tampered));
        let error = vault.open_sidecar(FileKind::Meta).unwrap_err();
        let expected = if (12..28).contains(&offset) {
            VaultError::SidecarVaultMismatch(FileKind::Meta)
        } else {
            VaultError::SidecarCorrupt(FileKind::Meta)
        };
        assert_eq!(error, expected, "offset {offset}");
    }

    // Another vault's meta (other vault_id, other DEK).
    let (other_storage, mut other) = imported(None);
    other.save_sidecar(FileKind::Meta, b"other").unwrap();
    storage.set_main(FileKind::Meta, other_storage.main(FileKind::Meta));
    assert_eq!(
        vault.open_sidecar(FileKind::Meta).err(),
        Some(VaultError::SidecarVaultMismatch(FileKind::Meta))
    );

    // Generation CAS: the file moved on (generation 7) behind the vault's back.
    storage.set_main(FileKind::Meta, Some(meta.clone()));
    vault.open_sidecar(FileKind::Meta).unwrap();
    let mut moved = meta;
    put(&mut moved, 28, &7_u64.to_be_bytes());
    storage.set_main(FileKind::Meta, Some(moved));
    let commits = storage.commits();
    assert_eq!(
        vault.save_sidecar(FileKind::Meta, b"meta-3"),
        Err(VaultError::Storage(StorageError::GenerationConflict))
    );
    assert_eq!(storage.commits(), commits);
    assert_eq!(
        vault.open_sidecar(FileKind::Vault).err(),
        Some(VaultError::InvalidState)
    );
    assert_eq!(
        vault.save_sidecar(FileKind::Vault, b"x").err(),
        Some(VaultError::InvalidState)
    );
}

#[test]
fn storage_commit_contract() {
    let mut storage = MemStorage::new(KDF_TEST);
    let first = seal_fixed(&KDF_TEST);
    storage.commit(FileKind::Vault, None, &first).unwrap();
    assert_eq!(
        storage.commit(FileKind::Vault, None, &first),
        Err(StorageError::AlreadyExists)
    );
    assert_eq!(
        storage.commit(FileKind::Vault, Some(2), &first),
        Err(StorageError::GenerationConflict)
    );
    let mut corrupt = first.clone();
    corrupt.truncate(100);
    storage.set_main(FileKind::Vault, Some(corrupt.clone()));
    assert_eq!(
        storage.commit(FileKind::Vault, Some(1), &first),
        Err(StorageError::Corrupt)
    );
    assert_eq!(storage.main(FileKind::Vault), Some(corrupt));
    storage.set_main(FileKind::Vault, Some(first.clone()));
    let mut second = first.clone();
    put(&mut second, 130, &2_u64.to_be_bytes());
    storage.commit(FileKind::Vault, Some(1), &second).unwrap();
    assert_eq!(storage.prev(FileKind::Vault), Some(first));
    assert_eq!(storage.main(FileKind::Vault), Some(second));
}

// ---------------------------------------------------------------- §6.3 load and recovery

#[test]
fn load_classification_and_recovery_from_prev() {
    let (storage, vault) = imported(None);
    drop(vault);
    let generation_one = storage.main(FileKind::Vault).unwrap();
    assert_eq!(reload(&storage).status(), VaultStatus::Locked);

    // Make a second generation so .prev exists, then damage the main file.
    let mut vault = reload(&storage);
    vault.unlock(&pw(PASSWORD), new_slot()).unwrap();
    vault.import_evm_private_key(&"07".repeat(32), 2).unwrap();
    drop(vault);
    let mut damaged = storage.main(FileKind::Vault).unwrap();
    damaged.truncate(150);
    storage.set_main(FileKind::Vault, Some(damaged.clone()));
    let mut vault = reload(&storage);
    assert_eq!(
        vault.status(),
        VaultStatus::Corrupt {
            prev_available: true
        }
    );
    assert_eq!(
        vault.unlock(&pw(PASSWORD), new_slot()),
        Err(VaultError::InvalidState)
    );
    assert_eq!(
        vault.recover_from_prev(&pw(OTHER_PASSWORD), new_slot(), 99),
        Err(VaultError::UnlockFailed)
    );
    assert_eq!(storage.main(FileKind::Vault), Some(damaged.clone()));
    assert_eq!(
        vault.recover_from_prev(&pw(PASSWORD), new_slot(), 99),
        Ok(VaultStatus::Unlocked {
            alt_passphrase: false
        })
    );
    assert_eq!(storage.quarantined(FileKind::Vault), vec![(99, damaged)]);
    let recovered = storage.main(FileKind::Vault).unwrap();
    assert_eq!(at(&recovered, 0..130), at(&generation_one, 0..130));
    assert_eq!(
        peek_generation_with(FileKind::Vault, &recovered, &KDF_TEST),
        Some(2)
    );
    assert!(
        vault.raw_keys().unwrap().is_empty(),
        "newer changes in the damaged file are lost"
    );

    // Main missing, .prev present.
    storage.set_main(FileKind::Vault, None);
    let mut vault = reload(&storage);
    assert_eq!(vault.status(), VaultStatus::MainMissing);
    assert_eq!(
        vault.recover_from_prev(&pw(PASSWORD), new_slot(), 100),
        Ok(VaultStatus::Unlocked {
            alt_passphrase: false
        })
    );

    // Nothing at all.
    storage.set_main(FileKind::Vault, None);
    storage.set_prev(FileKind::Vault, None);
    let mut vault = reload(&storage);
    assert_eq!(vault.status(), VaultStatus::NoVault);
    assert_eq!(
        vault.recover_from_prev(&pw(PASSWORD), new_slot(), 1),
        Err(VaultError::InvalidState)
    );
}

#[test]
fn payload_corrupt_at_unlock_offers_prev_recovery() {
    let (storage, mut vault) = imported(None);
    vault.import_evm_private_key(&"07".repeat(32), 2).unwrap();
    drop(vault);
    let mut main = storage.main(FileKind::Vault).unwrap();
    flip(&mut main, 200);
    storage.set_main(FileKind::Vault, Some(main.clone()));
    let mut vault = reload(&storage);
    assert_eq!(vault.status(), VaultStatus::Locked);
    assert_eq!(
        vault.unlock(&pw(PASSWORD), new_slot()),
        Err(VaultError::PayloadCorrupt)
    );
    assert_eq!(
        vault.status(),
        VaultStatus::Corrupt {
            prev_available: true
        }
    );
    assert_eq!(storage.main(FileKind::Vault), Some(main));
    assert_eq!(
        vault.recover_from_prev(&pw(PASSWORD), new_slot(), 5),
        Ok(VaultStatus::Unlocked {
            alt_passphrase: false
        })
    );
}

// ---------------------------------------------------------------- §11.8 state machine

#[test]
fn transitions_and_invalid_calls() {
    let (_, mut vault) = empty_vault(KDF_TEST);
    assert_eq!(vault.status(), VaultStatus::NoVault);
    assert_eq!(
        vault.unlock(&pw(PASSWORD), new_slot()),
        Err(VaultError::InvalidState)
    );
    assert_eq!(
        vault.enter_passphrase(Bip39Passphrase::new("x").unwrap()),
        Err(VaultError::InvalidState)
    );
    assert_eq!(vault.retry_passphrase(), Err(VaultError::InvalidState));
    assert_eq!(
        vault.accept_mismatched_passphrase(),
        Err(VaultError::InvalidState)
    );
    assert_eq!(
        vault.backup_challenge().err(),
        Some(VaultError::InvalidState)
    );
    assert_eq!(
        vault.evm_address(EvmKeySource::Derived(index(0))).err(),
        Some(VaultError::InvalidState)
    );
    assert_eq!(
        vault.reveal_mnemonic(&pw(PASSWORD)).err(),
        Some(VaultError::InvalidState)
    );
    assert_eq!(
        vault.open_sidecar(FileKind::Meta).err(),
        Some(VaultError::InvalidState)
    );
    assert_eq!(vault.vault_id(), None);
    vault.lock();
    assert_eq!(vault.status(), VaultStatus::NoVault);

    let (storage, mut vault, _) = created();
    assert_eq!(vault.status(), VaultStatus::BackupPending);
    assert_eq!(
        vault.create_wallet(&pw(PASSWORD), new_slot(), 1).err(),
        Some(VaultError::InvalidState)
    );
    assert_eq!(
        vault.import_mnemonic(&pw(PASSWORD), ABOUT, None, new_slot(), 1),
        Err(VaultError::InvalidState)
    );
    assert_eq!(
        vault.unlock(&pw(PASSWORD), new_slot()),
        Err(VaultError::InvalidState)
    );
    vault.lock();
    assert_eq!(vault.status(), VaultStatus::Locked);
    assert_eq!(
        vault.unlock(&pw(OTHER_PASSWORD), new_slot()),
        Err(VaultError::UnlockFailed)
    );
    assert_eq!(vault.status(), VaultStatus::Locked);
    assert_eq!(
        vault.unlock(&pw(PASSWORD), new_slot()),
        Ok(VaultStatus::BackupPending)
    );
    assert_eq!(reload(&storage).status(), VaultStatus::Locked);

    let (_, mut vault) = imported(None);
    assert_eq!(
        vault.status(),
        VaultStatus::Unlocked {
            alt_passphrase: false
        }
    );
    assert_eq!(
        vault.backup_challenge().err(),
        Some(VaultError::InvalidState)
    );
    assert_eq!(
        vault.enter_passphrase(Bip39Passphrase::new("x").unwrap()),
        Err(VaultError::InvalidState)
    );
    vault.lock();
    assert_eq!(
        vault.unlock(&pw(PASSWORD), new_slot()),
        Ok(VaultStatus::Unlocked {
            alt_passphrase: false
        })
    );
}

#[test]
fn backup_pending_blocks_signing_but_shows_addresses() {
    let (_, mut vault, phrase) = created();
    assert_eq!(phrase.expose().split(' ').count(), 24);
    assert!(vault.evm_address(EvmKeySource::Derived(index(0))).is_ok());
    assert_eq!(vault.evm_addresses(&[index(0), index(1)]).unwrap().len(), 2);
    assert_eq!(
        vault.with_secp_key(KeyRef::Evm(EvmKeySource::Derived(index(0))), |_, _| Ok(())),
        Err(VaultError::BackupNotConfirmed)
    );
    assert_eq!(
        vault
            .reveal_evm_private_key(&pw(PASSWORD), EvmKeySource::Derived(index(0)))
            .err(),
        Some(VaultError::BackupNotConfirmed)
    );
    assert_eq!(
        vault.import_evm_private_key(&"07".repeat(32), 1),
        Err(VaultError::BackupNotConfirmed)
    );
    assert_eq!(
        vault.reveal_mnemonic(&pw(PASSWORD)).unwrap().expose(),
        phrase.expose()
    );
    assert_eq!(
        vault.reveal_mnemonic(&pw(OTHER_PASSWORD)).err(),
        Some(VaultError::UnlockFailed)
    );
}

#[test]
fn lock_wipes_the_slot() {
    let (_, mut vault) = empty_vault(KDF_TEST);
    let (slot, wiped) = slot();
    vault
        .import_mnemonic(&pw(PASSWORD), ABOUT, None, slot, 1)
        .unwrap();
    assert!(!wiped.load(Ordering::SeqCst));
    assert_eq!(vault.slot_bytes().unwrap().get(32), Some(&0));
    vault.lock();
    assert!(wiped.load(Ordering::SeqCst));
    assert_eq!(vault.status(), VaultStatus::Locked);
    assert!(vault.slot_bytes().is_none());
    assert!(vault.held_bytes().is_none());
    assert_eq!(
        vault.evm_address(EvmKeySource::Derived(index(0))).err(),
        Some(VaultError::InvalidState)
    );
}

#[test]
fn passphrase_match_mismatch_accept_and_retry() {
    let (storage, mut vault) = imported(Some("TREZOR"));
    assert_eq!(
        vault.status(),
        VaultStatus::Unlocked {
            alt_passphrase: false
        }
    );
    assert_eq!(
        vault
            .evm_address(EvmKeySource::Derived(index(0)))
            .unwrap()
            .to_checksum(),
        "0x9c32F71D4DB8Fb9e1A58B0a80dF79935e7256FA6"
    );
    // Stored check value = SHA-256(addr0)[0..4] = dc929830 (ACC-4).
    let payload = vault.payload().unwrap();
    assert_eq!(
        hex::encode(&payload.bip39.first().unwrap().passphrase_check),
        "dc929830"
    );
    vault.lock();

    assert_eq!(
        vault.unlock(&pw(PASSWORD), new_slot()),
        Ok(VaultStatus::PassphraseRequired)
    );
    assert_eq!(
        vault.evm_address(EvmKeySource::Derived(index(0))).err(),
        Some(VaultError::InvalidState)
    );
    assert_eq!(
        vault.enter_passphrase(Bip39Passphrase::empty()),
        Err(VaultError::Key(KeyError::PassphraseEmpty))
    );
    assert_eq!(
        vault.enter_passphrase(Bip39Passphrase::new("TREZOR").unwrap()),
        Ok(VaultStatus::Unlocked {
            alt_passphrase: false
        })
    );
    vault.lock();

    vault.unlock(&pw(PASSWORD), new_slot()).unwrap();
    assert_eq!(
        vault.enter_passphrase(Bip39Passphrase::new(" TREZOR").unwrap()),
        Ok(VaultStatus::PassphraseMismatch)
    );
    assert_eq!(vault.slot_bytes().unwrap().get(32), Some(&1));
    assert_eq!(
        vault.retry_passphrase(),
        Ok(VaultStatus::PassphraseRequired)
    );
    assert!(
        vault
            .slot_bytes()
            .unwrap()
            .get(32..SLOT_LEN)
            .unwrap()
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(
        vault.enter_passphrase(Bip39Passphrase::new("trezor").unwrap()),
        Ok(VaultStatus::PassphraseMismatch)
    );
    assert_eq!(
        vault.accept_mismatched_passphrase(),
        Ok(VaultStatus::Unlocked {
            alt_passphrase: true
        })
    );
    let alt = vault.evm_address(EvmKeySource::Derived(index(0))).unwrap();
    assert_ne!(
        alt.to_checksum(),
        "0x9c32F71D4DB8Fb9e1A58B0a80dF79935e7256FA6"
    );
    assert_eq!(
        storage.commits(),
        1,
        "an alt session changes nothing on disk"
    );

    assert_eq!(
        vault.import_mnemonic(
            &pw(PASSWORD),
            ABOUT,
            Some(Bip39Passphrase::empty()),
            new_slot(),
            1
        ),
        Err(VaultError::InvalidState)
    );
    let (_, mut fresh) = empty_vault(KDF_TEST);
    assert_eq!(
        fresh.import_mnemonic(
            &pw(PASSWORD),
            ABOUT,
            Some(Bip39Passphrase::empty()),
            new_slot(),
            1
        ),
        Err(VaultError::Key(KeyError::PassphraseEmpty))
    );
}

fn challenge_script() -> Vec<u8> {
    // random_below(24) = 5, (23) = 7, (22) = 0, (21) = 20 → swaps give 1-based [3, 6, 9, 24].
    [5_u32, 7, 0, 20]
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

fn answers(phrase: &str, positions: [u8; 4]) -> [String; 4] {
    let words: Vec<&str> = phrase.split(' ').collect();
    positions.map(|position| (*words.get(usize::from(position) - 1).unwrap()).to_owned())
}

fn refs(values: &[String; 4]) -> [&str; 4] {
    let [a, b, c, d] = values;
    [a.as_str(), b.as_str(), c.as_str(), d.as_str()]
}

fn altered(mut words: [String; 4], position: usize, change: fn(&str) -> String) -> [String; 4] {
    let word = words.get_mut(position).unwrap();
    *word = change(word);
    words
}

#[test]
fn backup_confirmation() {
    let (storage, mut vault, phrase) = created();
    let challenge = vault
        .backup_challenge_with_rng(&mut ScriptedRandom::new(&challenge_script()))
        .unwrap();
    assert_eq!(challenge.positions, [3, 6, 9, 24]);

    // Each failure is BackupMismatch, discards the challenge, and stays in BackupPending; the
    // next challenge asks the same positions again (with a new id).
    let mut asked: Option<[u8; 4]> = None;
    let other_word: fn(&str) -> String = |word| {
        if word == "zoo" {
            "abandon".to_owned()
        } else {
            "zoo".to_owned()
        }
    };
    let upper: fn(&str) -> String = str::to_ascii_uppercase;
    let too_long: fn(&str) -> String = |_| "abandonnn".to_owned();
    let empty: fn(&str) -> String = |_| String::new();
    let non_letter: fn(&str) -> String = |word| format!("{word}1");
    for (label, position, change) in [
        ("word", 2, other_word),
        ("uppercase", 0, upper),
        ("long word", 3, too_long),
        ("empty word", 1, empty),
        ("non-letter", 1, non_letter),
    ] {
        let challenge = vault.backup_challenge().unwrap();
        if let Some(previous) = asked {
            assert_eq!(challenge.positions, previous, "{label}: same positions");
        }
        asked = Some(challenge.positions);
        let expected = answers(phrase.expose(), challenge.positions);
        let words = altered(expected.clone(), position, change);
        assert_eq!(
            vault.confirm_backup(challenge.id, refs(&words)),
            Err(VaultError::BackupMismatch),
            "{label}"
        );
        assert_eq!(vault.status(), VaultStatus::BackupPending);
        assert_eq!(
            vault.confirm_backup(challenge.id, refs(&expected)),
            Err(VaultError::ChallengeStale),
            "{label}"
        );
    }

    // A stale id is rejected while the current challenge stays usable.
    let stale = vault.backup_challenge().unwrap();
    let current = vault
        .backup_challenge_with_rng(&mut ScriptedRandom::new(&challenge_script()))
        .unwrap();
    assert_eq!(
        vault.confirm_backup(stale.id, refs(&answers(phrase.expose(), stale.positions))),
        Err(VaultError::ChallengeStale)
    );
    assert_eq!(vault.status(), VaultStatus::BackupPending);
    let commits = storage.commits();
    vault
        .confirm_backup(
            current.id,
            refs(&answers(phrase.expose(), current.positions)),
        )
        .unwrap();
    assert_eq!(
        vault.status(),
        VaultStatus::Unlocked {
            alt_passphrase: false
        }
    );
    assert_eq!(storage.commits(), commits + 1);
    vault.lock();
    assert_eq!(
        vault.unlock(&pw(PASSWORD), new_slot()),
        Ok(VaultStatus::Unlocked {
            alt_passphrase: false
        })
    );
}

#[test]
fn challenge_positions_are_distinct_ascending_and_in_range() {
    let (_, mut vault, _) = created();
    for _ in 0..200 {
        let challenge = vault.backup_challenge().unwrap();
        assert!(
            challenge
                .positions
                .windows(2)
                .all(|pair| pair.first() < pair.last())
        );
        assert!(
            challenge
                .positions
                .iter()
                .all(|position| (1..=24).contains(position))
        );
    }
}

#[test]
fn raw_keys_limits_duplicates_reveal_and_remove() {
    let (_, mut vault) = imported(None);
    for invalid in [
        String::new(),
        format!("0X{}", "07".repeat(32)),
        "00".repeat(32),
        "07".repeat(31),
        format!("{}0", "07".repeat(32)),
        format!(" {}", "07".repeat(32)),
        "gg".repeat(32),
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141".to_owned(),
    ] {
        assert_eq!(
            vault.import_evm_private_key(&invalid, 1),
            Err(VaultError::Key(KeyError::InvalidPrivateKey)),
            "{invalid:?}"
        );
    }
    let first = vault
        .import_evm_private_key(&format!("0x{}", "07".repeat(32)), 1)
        .unwrap();
    assert_eq!(
        vault.import_evm_private_key(&"07".repeat(32).to_ascii_uppercase(), 1),
        Err(VaultError::DuplicateKey)
    );
    for byte in 8..22_u8 {
        vault
            .import_evm_private_key(&hex::encode(&[byte; 32]), 1)
            .unwrap();
    }
    assert_eq!(vault.raw_keys().unwrap().len(), 15);
    assert_eq!(
        vault.import_evm_private_key(&"77".repeat(32), 1),
        Err(VaultError::RecordLimit)
    );
    assert_eq!(
        vault
            .reveal_evm_private_key(&pw(PASSWORD), EvmKeySource::Raw(first))
            .unwrap()
            .expose(),
        "07".repeat(32)
    );
    assert_eq!(
        vault
            .reveal_evm_private_key(&pw(PASSWORD), EvmKeySource::Derived(index(0)))
            .unwrap()
            .expose(),
        "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"
    );
    assert_eq!(
        vault.remove_evm_raw_key(&pw(OTHER_PASSWORD), first),
        Err(VaultError::UnlockFailed)
    );
    vault.remove_evm_raw_key(&pw(PASSWORD), first).unwrap();
    assert_eq!(
        vault.remove_evm_raw_key(&pw(PASSWORD), first),
        Err(VaultError::RecordNotFound)
    );
    assert_eq!(
        vault.evm_address(EvmKeySource::Raw(first)).err(),
        Some(VaultError::RecordNotFound)
    );
    assert_eq!(vault.raw_keys().unwrap().len(), 14);
    let unknown = RecordId::from_bytes([0xee; 16]);
    assert_eq!(unknown.as_bytes(), &[0xee; 16]);
}

#[test]
fn derived_addresses_signing_key_and_batch_limit() {
    let (_, vault) = imported(None);
    let addresses = vault.evm_addresses(&[index(0), index(1)]).unwrap();
    let rendered: Vec<String> = addresses
        .iter()
        .map(|address| address.to_checksum())
        .collect();
    assert_eq!(
        rendered,
        [
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
            "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0"
        ]
    );
    let too_many: Vec<AccountIndex> = (0..101).map(index).collect();
    assert_eq!(
        vault.evm_addresses(&too_many).err(),
        Some(VaultError::InvalidState)
    );
    let key = vault
        .with_secp_key(KeyRef::Evm(EvmKeySource::Derived(index(1))), |_, secret| {
            Ok(hex::encode(&secret.secret_bytes()))
        })
        .unwrap();
    assert_eq!(
        key,
        "9a983cb3d832fbde5ab49d692b7a8bf5b5d232479c99333d0fc8e1d21f1b55b6"
    );
    let btc = vault
        .with_secp_key(
            KeyRef::Btc {
                mnemonic: None,
                coin: BtcCoin::Mainnet,
                chain: BtcChain::Receive,
                index: 0,
            },
            |ctx, secret| {
                Ok(hex::encode(
                    &secp256k1::PublicKey::from_secret_key(ctx, secret).serialize(),
                ))
            },
        )
        .unwrap();
    assert_eq!(
        btc,
        "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
    );
}

#[test]
fn debug_output_is_redacted() {
    let marker = "07".repeat(32);
    let password = pw(b"marker-password-xyz");
    let (_, mut vault) = imported(Some("SECRETPASS"));
    vault.import_evm_private_key(&marker, 1).unwrap();
    let payload = vault.payload().unwrap();
    for rendered in [
        format!("{password:?}"),
        format!("{:?}", Bip39Passphrase::new("SECRETPASS").unwrap()),
        format!("{:?}", payload.bip39.first().unwrap().mnemonic),
        format!("{vault:?}"),
        format!("{:?}", vault.backup_challenge().err()),
    ] {
        assert!(!rendered.contains("marker-password"), "{rendered}");
        assert!(!rendered.contains("SECRETPASS"), "{rendered}");
        assert!(!rendered.contains("abandon"), "{rendered}");
        assert!(!rendered.contains(&marker), "{rendered}");
    }
    assert_eq!(
        format!("{vault:?}"),
        "Vault { status: Unlocked { alt_passphrase: false }, .. }"
    );
}

#[test]
fn vault_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<Vault>();
}

// ---------------------------------------------------------------- manual tools (ignored)

/// spec/09 §2.4 fallback for the `vault_header` fuzz target (cargo-fuzz not used): xorshift64*
/// (fixed seed) bit flips, inserts, deletes and truncations of the golden files, 1,000,000 runs.
/// Invariants: no panic, `peek_generation` agrees with `check_vault_header`, and no Argon2 call.
/// Run: `cargo test --release -p yw-core --lib vault::tests::fuzz_lite_vault_header -- --ignored`.
#[test]
#[ignore = "manual fuzz fallback (spec/09 §2.4); run in release"]
fn fuzz_lite_vault_header() {
    const SEED: u64 = 0x5957_564c_5430_3033;
    const MAX_LEN: usize = 4_096;
    // `YW_FUZZ_RUNS` (the short smoke run of `scripts/check.ps1`) or 1,000,000.
    #[expect(
        clippy::disallowed_methods,
        reason = "the iteration count of a test tool; yw-core itself never reads the environment"
    )]
    let runs: u32 = std::env::var("YW_FUZZ_RUNS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&runs| runs > 0)
        .unwrap_or(1_000_000);
    let seeds = [seal_fixed(&KDF_V3), seal_fixed(&KDF_TEST)];
    let mut state = SEED;
    let mut next = move |bound: usize| {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let value = state.wrapping_mul(0x2545_f491_4f6c_dd1d);
        usize::try_from(value % u64::try_from(bound.max(1)).unwrap()).unwrap()
    };
    let before = kdf_calls();
    let mut accepted = 0_u32;
    for _ in 0..runs {
        let mut input = seeds.get(next(seeds.len())).unwrap().clone();
        for _ in 0..=next(4) {
            match next(4) {
                0 if !input.is_empty() => {
                    let at = next(input.len());
                    *input.get_mut(at).unwrap() ^= 1 << next(8);
                }
                1 if input.len() < MAX_LEN => {
                    let at = next(input.len() + 1);
                    input.insert(at, u8::try_from(next(256)).unwrap());
                }
                2 if !input.is_empty() => {
                    input.remove(next(input.len()));
                }
                3 => input.truncate(next(input.len() + 1)),
                _ => {}
            }
        }
        let checked = check_vault_header(&input);
        assert_eq!(peek_generation(FileKind::Vault, &input), checked.ok());
        let _ = peek_generation_with(FileKind::Vault, &input, &KDF_TEST);
        let _ = peek_generation(FileKind::Meta, &input);
        let _ = peek_generation(FileKind::Journal, &input);
        accepted += u32::from(checked.is_ok());
    }
    assert_eq!(kdf_calls(), before);
    assert!(accepted > 0 && accepted < runs);
}

/// spec/09 §5.2 M1-4: exactly one production Argon2id (256 MiB, t = 3, p = 4) for timing the
/// release build from outside (`Measure-Command`); yw-core itself never reads a clock.
#[test]
#[ignore = "manual timing tool (spec/02 §7.4)"]
fn argon2_production_single_derivation() {
    let before = kdf_calls();
    let kek = format::derive_kek(&pw(GOLDEN_PASSWORD), &seq(0x40), &KDF_V3).unwrap();
    assert_eq!(kdf_calls() - before, 1);
    assert_ne!(kek.as_slice(), [0; 32]);
}

#[test]
fn lock_from_passphrase_states() {
    let (_, mut vault) = imported(Some("TREZOR"));
    vault.lock();
    assert_eq!(
        vault.unlock(&pw(PASSWORD), new_slot()),
        Ok(VaultStatus::PassphraseRequired)
    );
    vault.lock();
    assert_eq!(vault.status(), VaultStatus::Locked);
    vault.unlock(&pw(PASSWORD), new_slot()).unwrap();
    assert_eq!(
        vault.enter_passphrase(Bip39Passphrase::new("wrong").unwrap()),
        Ok(VaultStatus::PassphraseMismatch)
    );
    vault.lock();
    assert_eq!(vault.status(), VaultStatus::Locked);
    assert!(vault.slot_bytes().is_none());
}

// ---------------------------------------------------------------- Solana (M7, spec/02 §11.5)

/// An unlocked test vault (fast KDF) holding `phrase`, for the Solana signing tests.
pub(crate) fn unlocked_with(phrase: &str) -> Vault {
    let (_, mut vault) = empty_vault(KDF_TEST);
    vault
        .import_mnemonic(&pw(PASSWORD), phrase, None, new_slot(), 1_790_000_000)
        .unwrap();
    vault
}

/// An unlocked vault of `primary` with `added` as a second mnemonic (backup confirmed).
pub(crate) fn unlocked_with_added(primary: &str, added: &str) -> (Vault, RecordId) {
    let mut vault = unlocked_with(primary);
    let id = vault
        .add_mnemonic(&pw(PASSWORD), added, None, 1_790_000_001)
        .unwrap();
    (vault, id)
}

fn sol_b58(key: &[u8; 32]) -> String {
    crate::codec::base58::encode(key)
}

/// spec/07 §17.1 table, `abandon`×11 `about` and `abandon`×23 `art`, through one
/// `sol_public_keys` call per mnemonic; output order = input order.
#[test]
fn sol_key_sources_reproduce_the_spec07_table() {
    use crate::slip10::SolKeySource;
    let index = |i| AccountIndex::new(i).unwrap();
    let sources = [
        SolKeySource::Standard(index(0)),
        SolKeySource::Standard(index(1)),
        SolKeySource::Standard(index(2)),
        SolKeySource::Bip44Account(index(0)),
        SolKeySource::Bip44Account(index(1)),
        SolKeySource::Bip44Root,
        SolKeySource::RawSeed,
    ];
    let about = [
        "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
        "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb",
        "7WktogJEd2wQ9eH2oWusmcoFTgeYi6rS632UviTBJ2jm",
        "GjJyeC1r2RgkuoCWMyPYkCWSGSGLcz266EaAkLA27AhL",
        "ANf3TEKFL6jPWjzkndo4CbnNdUNkBk4KHPggJs2nu8Xi",
        "D2PPQSYFe83nDzk96FqGumVU8JA7J8vj2Rhjc2oXzEi5",
        "EHqmfkN89RJ7Y33CXM6uCzhVeuywHoJXZZLszBHHZy7o",
    ];
    let art = [
        "3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx",
        "5frqxtii9LeGq2bz3dSNokvZcEooF483MzeU24JrhcTA",
        "3SuKj3MZU9dMZ9oR1R7afttihZFkWpfUmduuv9rmfMa1",
        "4BZp4ci5rhNYqbayj1uppeTas1osK2Q4b74x7UENC5Hd",
        "7bDLWB6YMdFHVRonYoTzikCFSoC5Ls4SKxbnydpLTPCM",
        "BkWizA4ezeYB3jbixzPnzj6r2QuGekZXXFQHstDJE8wK",
        "31fsSBAugfgtWp4WZLgr1D9TBkgiS13d5eK3GWBQwRct",
    ];
    let art_phrase = Mnemonic::from_entropy(&[0; 32]).unwrap().phrase().unwrap();
    for (phrase, expected) in [(ABOUT, about), (art_phrase.expose(), art)] {
        let vault = unlocked_with(phrase);
        let keys = vault.sol_public_keys(&sources).unwrap();
        let shown: Vec<String> = keys.iter().map(sol_b58).collect();
        assert_eq!(shown, expected);
        // Reversed input → reversed output.
        let mut reversed = sources;
        reversed.reverse();
        let mut back: Vec<String> = vault
            .sol_public_keys(&reversed)
            .unwrap()
            .iter()
            .map(sol_b58)
            .collect();
        back.reverse();
        assert_eq!(back, expected);
    }
    let vault = unlocked_with(ABOUT);
    assert_eq!(
        hex::encode(
            vault
                .sol_public_keys(&sources[..1])
                .unwrap()
                .first()
                .unwrap()
        ),
        "f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7"
    );
}

#[test]
fn sol_public_keys_bounds_states_and_sollet() {
    use crate::slip10::SolKeySource;
    let vault = unlocked_with(ABOUT);
    let many = vec![SolKeySource::Bip44Root; 128];
    assert_eq!(vault.sol_public_keys(&many).unwrap().len(), 128);
    let too_many = vec![SolKeySource::Bip44Root; 129];
    assert_eq!(
        vault.sol_public_keys(&too_many),
        Err(VaultError::InvalidState)
    );
    assert_eq!(vault.sol_public_keys(&[]), Ok(Vec::new()));
    assert_eq!(
        vault.sol_public_keys(&[SolKeySource::SolletLegacy {
            wallet: 0,
            account: 0
        }]),
        Err(VaultError::Key(KeyError::InvalidPath))
    );
    // Created wallets are BackupPending: public keys yes, signing seed no.
    let (_, pending, _) = created();
    assert!(pending.sol_public_keys(&[SolKeySource::RawSeed]).is_ok());
    assert_eq!(
        pending.with_ed25519_seed(SolKeySource::RawSeed, |_| Ok(())),
        Err(VaultError::BackupNotConfirmed)
    );
    let (_, mut locked) = imported(None);
    locked.lock();
    assert_eq!(
        locked.sol_public_keys(&[SolKeySource::RawSeed]),
        Err(VaultError::InvalidState)
    );
}

#[test]
fn with_ed25519_seed_lends_the_spec_seeds() {
    use crate::slip10::SolKeySource;
    let vault = unlocked_with(ABOUT);
    let standard = vault
        .with_ed25519_seed(SolKeySource::Standard(AccountIndex::ZERO), |seed| {
            Ok(hex::encode(seed))
        })
        .unwrap();
    assert_eq!(
        standard,
        "37df573b3ac4ad5b522e064e25b63ea16bcbe79d449e81a0268d1047948bb445"
    );
    let raw = vault
        .with_ed25519_seed(SolKeySource::RawSeed, |seed| Ok(hex::encode(seed)))
        .unwrap();
    assert_eq!(
        raw,
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    );
    assert_eq!(
        vault.with_ed25519_seed(SolKeySource::RawSeed, |_| -> Result<(), VaultError> {
            Err(VaultError::RecordNotFound)
        }),
        Err(VaultError::RecordNotFound)
    );
}

// ---------------------------------------------------------------- Bitcoin (M8, spec/02 §10.3)

/// Public Bitcoin information is available in `BackupPending` and `Unlocked`, not when locked;
/// hardened leaf indices are refused before anything is derived.
#[test]
fn btc_public_info_states() {
    let (_, pending, _) = created();
    assert_eq!(pending.status(), VaultStatus::BackupPending);
    let account = pending.btc_account_xpub(BtcCoin::Mainnet).unwrap();
    assert!(matches!(account.pubkey.first(), Some(0x02 | 0x03)));
    let leaf = pending
        .btc_public_key(BtcCoin::Test, BtcChain::Change, 7)
        .unwrap();
    assert_eq!(
        crate::bip32::derive_public_child(
            &crate::bip32::derive_public_child(
                &pending.btc_account_xpub(BtcCoin::Test).unwrap(),
                1
            )
            .unwrap(),
            7
        )
        .unwrap()
        .pubkey,
        leaf
    );
    let (_, mut vault) = imported(None);
    assert_eq!(
        vault.btc_public_key(BtcCoin::Mainnet, BtcChain::Receive, 0x8000_0000),
        Err(VaultError::Key(KeyError::InvalidPath))
    );
    vault.lock();
    assert_eq!(
        vault.btc_account_xpub(BtcCoin::Mainnet),
        Err(VaultError::InvalidState)
    );
    assert_eq!(
        vault.btc_public_key(BtcCoin::Mainnet, BtcChain::Receive, 0),
        Err(VaultError::InvalidState)
    );
    // A passphrase changes the account node.
    let (_, with_passphrase) = imported(Some("TREZOR"));
    let (_, without) = imported(None);
    assert_ne!(
        with_passphrase.btc_account_xpub(BtcCoin::Mainnet).unwrap(),
        without.btc_account_xpub(BtcCoin::Mainnet).unwrap()
    );
}

// ---------------------------------------------------------------- review fixes

#[test]
fn recover_from_locked_restores_only_an_unopenable_main_file() {
    let (storage, mut vault) = imported(None);
    vault.import_evm_private_key(&"07".repeat(32), 2).unwrap();
    drop(vault);
    let healthy = storage.main(FileKind::Vault).unwrap();
    let prev = storage.prev(FileKind::Vault).unwrap();

    // The main file opens: a plain unlock, nothing restored or quarantined.
    let mut vault = reload(&storage);
    assert_eq!(vault.status(), VaultStatus::Locked);
    assert_eq!(
        vault.recover_from_prev(&pw(PASSWORD), new_slot(), 7),
        Ok(VaultStatus::Unlocked {
            alt_passphrase: false
        })
    );
    assert_eq!(vault.raw_keys().unwrap().len(), 1);
    assert_eq!(storage.main(FileKind::Vault), Some(healthy.clone()));
    assert!(storage.quarantined(FileKind::Vault).is_empty());

    // Not from a session state.
    let (busy, wiped) = slot();
    assert_eq!(
        vault.recover_from_prev(&pw(PASSWORD), busy, 7),
        Err(VaultError::InvalidState)
    );
    assert!(wiped.load(Ordering::SeqCst));
    vault.lock();

    // A wrong password opens neither file and changes nothing.
    let (wrong, wiped) = slot();
    assert_eq!(
        vault.recover_from_prev(&pw(OTHER_PASSWORD), wrong, 8),
        Err(VaultError::UnlockFailed)
    );
    assert!(wiped.load(Ordering::SeqCst));
    assert_eq!(vault.status(), VaultStatus::Locked);
    assert_eq!(storage.main(FileKind::Vault), Some(healthy.clone()));
    assert!(storage.quarantined(FileKind::Vault).is_empty());

    // A damaged key section (wrapped DEK) looks like a wrong password to `unlock` …
    let mut damaged = healthy;
    flip(&mut damaged, 100);
    storage.set_main(FileKind::Vault, Some(damaged.clone()));
    let mut vault = reload(&storage);
    assert_eq!(vault.status(), VaultStatus::Locked);
    assert_eq!(
        vault.unlock(&pw(PASSWORD), new_slot()),
        Err(VaultError::UnlockFailed)
    );
    assert_eq!(vault.status(), VaultStatus::Locked);
    // … and the explicit recovery restores `.prev` and keeps the damaged file aside.
    assert_eq!(
        vault.recover_from_prev(&pw(PASSWORD), new_slot(), 9),
        Ok(VaultStatus::Unlocked {
            alt_passphrase: false
        })
    );
    assert_eq!(storage.quarantined(FileKind::Vault), vec![(9, damaged)]);
    assert!(
        vault.raw_keys().unwrap().is_empty(),
        "the newer change in the damaged file is lost"
    );
    let restored = storage.main(FileKind::Vault).unwrap();
    assert_eq!(at(&restored, 0..130), at(&prev, 0..130));
    assert_eq!(reload(&storage).status(), VaultStatus::Locked);

    // A damaged payload reached from `Locked` (a reload dropped the `Corrupt` status).
    let (storage, mut vault) = imported(None);
    vault.import_evm_private_key(&"07".repeat(32), 2).unwrap();
    drop(vault);
    let mut main = storage.main(FileKind::Vault).unwrap();
    flip(&mut main, 200);
    storage.set_main(FileKind::Vault, Some(main.clone()));
    let mut vault = reload(&storage);
    assert_eq!(
        vault.unlock(&pw(PASSWORD), new_slot()),
        Err(VaultError::PayloadCorrupt)
    );
    drop(vault);
    let mut vault = reload(&storage);
    assert_eq!(vault.status(), VaultStatus::Locked);
    assert_eq!(
        vault.recover_from_prev(&pw(PASSWORD), new_slot(), 10),
        Ok(VaultStatus::Unlocked {
            alt_passphrase: false
        })
    );
    assert_eq!(storage.quarantined(FileKind::Vault), vec![(10, main)]);
}

#[test]
fn commit_that_lands_but_reports_failure_is_success() {
    let (storage, mut vault) = empty_vault(KDF_TEST);
    storage.set_fail_after_write(true);
    let (created_slot, wiped) = slot();
    let phrase = vault.create_wallet(&pw(PASSWORD), created_slot, 1).unwrap();
    assert_eq!(phrase.expose().split(' ').count(), 24);
    assert_eq!(vault.status(), VaultStatus::BackupPending);
    assert!(!wiped.load(Ordering::SeqCst));
    assert_eq!(storage.commits(), 1);

    let (storage, mut vault) = imported(None);
    storage.set_fail_after_write(true);
    let id = vault.import_evm_private_key(&"07".repeat(32), 2).unwrap();
    assert_eq!(vault.raw_keys().unwrap().len(), 1);
    // The in-memory bytes followed the disk, so the next generation CAS still matches.
    vault
        .change_password(&pw(PASSWORD), &pw(b"new password 33"), &any_sidecar)
        .unwrap();
    assert_eq!(vault.save_sidecar(FileKind::Meta, b"meta-1"), Ok(1));
    assert_eq!(vault.save_sidecar(FileKind::Meta, b"meta-2"), Ok(2));
    vault
        .remove_evm_raw_key(&pw(b"new password 33"), id)
        .unwrap();
    storage.set_fail_after_write(false);
    vault.lock();
    assert_eq!(
        vault.unlock(&pw(b"new password 33"), new_slot()),
        Ok(VaultStatus::Unlocked {
            alt_passphrase: false
        })
    );
    assert!(vault.raw_keys().unwrap().is_empty());
    // A commit that did not land still fails and changes nothing.
    storage.set_fail_commits(true);
    assert_eq!(
        vault.import_evm_private_key(&"08".repeat(32), 3),
        Err(VaultError::Storage(StorageError::Io(5)))
    );
    assert!(vault.raw_keys().unwrap().is_empty());
}

#[test]
fn unauthenticated_sidecars_are_never_overwritten() {
    // Another vault's meta left in the folder: authenticated before any save, never replaced.
    let (other_storage, mut other) = imported(None);
    other.save_sidecar(FileKind::Meta, b"other").unwrap();
    let foreign = other_storage.main(FileKind::Meta).unwrap();
    let (storage, mut vault) = imported(None);
    storage.set_main(FileKind::Meta, Some(foreign.clone()));
    let commits = storage.commits();
    assert_eq!(
        vault.save_sidecar(FileKind::Meta, b"mine"),
        Err(VaultError::SidecarVaultMismatch(FileKind::Meta))
    );
    assert_eq!(storage.main(FileKind::Meta), Some(foreign));
    assert_eq!(storage.commits(), commits);

    // This vault's meta with a damaged tag: structurally valid, so the old code took its
    // generation and overwrote it. Now the failed open blocks every save.
    storage.set_main(FileKind::Meta, None);
    assert_eq!(
        vault.open_sidecar(FileKind::Meta).unwrap().map(|(g, _)| g),
        None
    );
    assert_eq!(vault.save_sidecar(FileKind::Meta, b"meta-1"), Ok(1));
    let mut damaged = storage.main(FileKind::Meta).unwrap();
    let last = damaged.len() - 1;
    flip(&mut damaged, last);
    storage.set_main(FileKind::Meta, Some(damaged.clone()));
    vault.lock();
    vault.unlock(&pw(PASSWORD), new_slot()).unwrap();
    let commits = storage.commits();
    assert_eq!(
        vault.save_sidecar(FileKind::Meta, b"meta-2"),
        Err(VaultError::SidecarCorrupt(FileKind::Meta))
    );
    assert_eq!(
        vault.open_sidecar(FileKind::Meta).err(),
        Some(VaultError::SidecarCorrupt(FileKind::Meta))
    );
    assert_eq!(
        vault.save_sidecar(FileKind::Meta, b"meta-2"),
        Err(VaultError::SidecarCorrupt(FileKind::Meta))
    );
    assert_eq!(storage.main(FileKind::Meta), Some(damaged));
    assert_eq!(storage.commits(), commits);
    // The journal is independent.
    assert_eq!(vault.save_sidecar(FileKind::Journal, b"journal"), Ok(1));

    // After the user quarantines the file, the next open finds none and saving resumes.
    storage.set_main(FileKind::Meta, None);
    assert_eq!(
        vault.open_sidecar(FileKind::Meta).unwrap().map(|(g, _)| g),
        None
    );
    assert_eq!(vault.save_sidecar(FileKind::Meta, b"fresh"), Ok(1));
}

#[test]
fn raw_key_records_never_reallocate() {
    let (_, mut vault) = imported(None);
    for byte in 1..=3_u8 {
        vault
            .import_evm_private_key(&format!("{byte:02x}").repeat(32), 1)
            .unwrap();
    }
    let mut payload = vault.payload().unwrap();
    assert_eq!(payload.raw_keys.len(), 3);
    assert_eq!(payload.raw_keys.capacity(), MAX_RAW_KEYS);
    let buffer = payload.raw_keys.as_ptr();
    payload.raw_keys.retain(|raw| raw.key.first() != Some(&2));
    for byte in 10_u8.. {
        if payload.raw_keys.len() == MAX_RAW_KEYS {
            break;
        }
        payload.raw_keys.push(raw_record(byte));
    }
    assert_eq!(
        payload.raw_keys.as_ptr(),
        buffer,
        "push moved the key records"
    );
    assert_eq!(payload.raw_keys.capacity(), MAX_RAW_KEYS);
    // A payload built for a new vault has the same fixed capacity.
    assert_eq!(format::raw_key_list().capacity(), MAX_RAW_KEYS);
}

#[test]
fn dropping_the_vault_wipes_the_slot() {
    let (_, mut vault) = empty_vault(KDF_TEST);
    let (slot, wiped) = slot();
    vault
        .import_mnemonic(&pw(PASSWORD), ABOUT, None, slot, 1)
        .unwrap();
    assert!(!wiped.load(Ordering::SeqCst));
    drop(vault);
    assert!(wiped.load(Ordering::SeqCst));
}

#[test]
fn secret_outputs_redact_debug() {
    let (_, mut vault) = imported(None);
    vault
        .save_sidecar(FileKind::Meta, b"meta plaintext")
        .unwrap();
    let phrase = vault.reveal_mnemonic(&pw(PASSWORD)).unwrap();
    assert_eq!(phrase.expose(), ABOUT);
    assert_eq!(format!("{phrase:?}"), "SecretString([REDACTED])");
    let key = vault
        .reveal_evm_private_key(&pw(PASSWORD), EvmKeySource::Derived(index(0)))
        .unwrap();
    assert_eq!(key.expose().len(), 64);
    assert_eq!(format!("{key:?}"), "SecretString([REDACTED])");
    let (_, plaintext) = vault.open_sidecar(FileKind::Meta).unwrap().unwrap();
    assert_eq!(plaintext.expose(), b"meta plaintext");
    assert_eq!(format!("{plaintext:?}"), "SecretVec([REDACTED])");
    let mnemonic = Mnemonic::parse(ABOUT).unwrap();
    assert_eq!(
        format!("{:?}", mnemonic.phrase().unwrap()),
        "SecretString([REDACTED])"
    );
    assert_eq!(
        format!("{:?}", mnemonic.to_seed(&Bip39Passphrase::empty()).unwrap()),
        "SecretBytes<64>([REDACTED])"
    );
    let (_, created_vault, created_phrase) = created();
    drop(created_vault);
    assert_eq!(format!("{created_phrase:?}"), "SecretString([REDACTED])");
}

// ---------------------------------------------------------------- imported keys (tags 3, 4) and
// key-only vaults (spec/02 §4.6, §8.4–§8.5, §11.9)

/// RFC 8032 test 1 seed (a public test vector).
const SOL_TEST_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
/// BIP84 test vector WIF (abandon mnemonic, `m/84'/0'/0'/0/0`).
const BIP84_TEST_WIF: &str = "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d";

fn sol_import(seed: [u8; 32]) -> crate::keyimport::ImportKey {
    let public = crate::sol::keys::public_key(&seed);
    crate::keyimport::ImportKey {
        inner: crate::keyimport::ImportInner::Sol {
            seed: Zeroizing::new(seed),
            public,
        },
    }
}

fn btc_import(
    secret: [u8; 32],
    compressed: bool,
    script: crate::btc::ScriptType,
) -> crate::keyimport::ImportKey {
    crate::keyimport::ImportKey {
        inner: crate::keyimport::ImportInner::Btc {
            secret: Zeroizing::new(secret),
            compressed,
            network: crate::btc::network::BtcNetwork::Mainnet,
            script,
        },
    }
}

fn evm_import(byte: u8) -> crate::keyimport::ImportKey {
    crate::keyimport::ImportKey::parse(crate::keyimport::ImportSpec::Evm, &hex::encode(&[byte; 32]))
        .unwrap()
}

/// A key-only test vault (fast KDF) holding `key`, for the Solana signing tests.
pub(crate) fn key_only_with(key: crate::keyimport::ImportKey) -> Vault {
    let (_, mut vault) = empty_vault(KDF_TEST);
    vault
        .create_with_key(&pw(PASSWORD), key, new_slot(), 1_790_000_000)
        .unwrap();
    vault
}

fn sol_record_bytes(id: u8, seed: [u8; 32], public: [u8; 32]) -> Vec<u8> {
    let mut out = vec![3];
    out.extend_from_slice(&[id; 16]);
    out.extend_from_slice(&8_u64.to_be_bytes());
    out.extend_from_slice(&seed);
    out.extend_from_slice(&public);
    out
}

fn btc_record_bytes(id: u8, secret: [u8; 32], flags: u8, network: u8, script: u8) -> Vec<u8> {
    let mut out = vec![4];
    out.extend_from_slice(&[id; 16]);
    out.extend_from_slice(&9_u64.to_be_bytes());
    out.extend_from_slice(&secret);
    out.push(flags);
    out.push(network);
    out.push(script);
    out
}

#[test]
fn old_layout_payload_decodes_and_re_encodes_identically() {
    // A payload as written before key import existed: Bip39 + EvmRawKey records only.
    let bytes = payload_bytes(
        &[
            bip39_record(1, 32, 0, 1, [0; 4]),
            raw_bytes(2, [3; 32]),
            raw_bytes(4, [5; 32]),
        ],
        3,
    );
    let payload = Payload::decode(&bytes).unwrap();
    assert!(!payload.bip39.is_empty());
    assert_eq!(payload.raw_keys.len(), 2);
    assert!(payload.sol_keys.is_empty() && payload.btc_keys.is_empty());
    assert_eq!(payload.encode().unwrap().as_slice(), bytes.as_slice());
}

#[test]
#[expect(clippy::too_many_lines, reason = "one table / one scenario")]
fn tagged_records_codec_and_rejections() {
    let sol_seed: [u8; 32] = hex::decode_array(SOL_TEST_SEED).unwrap();
    let sol_public = crate::sol::keys::public_key(&sol_seed);
    let good_sol = sol_record_bytes(5, sol_seed, sol_public);
    let good_btc = btc_record_bytes(6, [9; 32], 1, 1, 3);
    let bip39 = bip39_record(1, 16, 0, 1, [0; 4]);
    let raw = raw_bytes(2, [3; 32]);
    // Every tag together, and key-only payloads (no Bip39), decode and re-encode identically.
    for (records, count) in [
        (
            vec![
                bip39.clone(),
                raw.clone(),
                good_sol.clone(),
                good_btc.clone(),
            ],
            4,
        ),
        (vec![good_sol.clone()], 1),
        (vec![good_btc.clone()], 1),
        (vec![raw.clone(), good_btc.clone()], 2),
        // The same Bitcoin secret used as another script type is another account.
        (
            vec![good_btc.clone(), btc_record_bytes(7, [9; 32], 1, 1, 4)],
            2,
        ),
        // An uncompressed key as P2PKH.
        (vec![btc_record_bytes(7, [9; 32], 0, 2, 1)], 1),
    ] {
        let bytes = payload_bytes(&records, count);
        let payload = Payload::decode(&bytes).unwrap();
        assert_eq!(payload.encode().unwrap().as_slice(), bytes.as_slice());
    }
    let mut wrong_public = sol_public;
    flip(&mut wrong_public, 0);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "sol public mismatch",
            payload_bytes(&[sol_record_bytes(5, sol_seed, wrong_public)], 1),
        ),
        (
            "sol duplicate",
            payload_bytes(
                &[good_sol.clone(), sol_record_bytes(7, sol_seed, sol_public)],
                2,
            ),
        ),
        (
            "btc duplicate",
            payload_bytes(
                &[good_btc.clone(), btc_record_bytes(7, [9; 32], 1, 1, 3)],
                2,
            ),
        ),
        (
            "btc zero secret",
            payload_bytes(&[btc_record_bytes(7, [0; 32], 1, 1, 3)], 1),
        ),
        (
            "btc flags 2",
            payload_bytes(&[btc_record_bytes(7, [9; 32], 2, 1, 3)], 1),
        ),
        (
            "btc network 0",
            payload_bytes(&[btc_record_bytes(7, [9; 32], 1, 0, 3)], 1),
        ),
        (
            "btc network 3",
            payload_bytes(&[btc_record_bytes(7, [9; 32], 1, 3, 3)], 1),
        ),
        (
            "btc script 0",
            payload_bytes(&[btc_record_bytes(7, [9; 32], 1, 1, 0)], 1),
        ),
        (
            "btc script 5",
            payload_bytes(&[btc_record_bytes(7, [9; 32], 1, 1, 5)], 1),
        ),
        (
            "uncompressed segwit",
            payload_bytes(&[btc_record_bytes(7, [9; 32], 0, 1, 3)], 1),
        ),
        (
            "sol before raw",
            payload_bytes(&[good_sol.clone(), raw.clone()], 2),
        ),
        (
            "btc before sol",
            payload_bytes(&[good_btc.clone(), good_sol.clone()], 2),
        ),
        (
            "bip39 after raw",
            payload_bytes(&[raw.clone(), bip39.clone()], 2),
        ),
        (
            "record id shared across tags",
            payload_bytes(
                &[good_sol.clone(), btc_record_bytes(5, [9; 32], 1, 1, 3)],
                2,
            ),
        ),
        (
            // Tag 7 is only the `PrevDek` block after the records, never a counted record.
            "tag 7 as a record",
            payload_bytes(&[btc_record_bytes(7, [9; 32], 1, 1, 3)], 1)
                .into_iter()
                .enumerate()
                .map(|(at, byte)| if at == 16 { 7 } else { byte })
                .collect(),
        ),
        (
            "unknown tag 8",
            payload_bytes(&[btc_record_bytes(7, [9; 32], 1, 1, 3)], 1)
                .into_iter()
                .enumerate()
                .map(|(at, byte)| if at == 16 { 8 } else { byte })
                .collect(),
        ),
        (
            "count 70",
            payload_bytes(std::slice::from_ref(&good_sol), 70),
        ),
    ];
    for (label, bytes) in cases {
        assert_eq!(
            Payload::decode(&bytes).err(),
            Some(VaultError::UnsupportedPayload),
            "{label}"
        );
    }
}

#[test]
fn largest_payload_fits_and_seals() {
    // 24 words + 15 keys of each chain: 16 + 64 + 15 × (57 + 89 + 60) = 3,170 plaintext bytes.
    let mut payload = golden_payload();
    payload.raw_keys.extend((1..=15).map(raw_record));
    for byte in 1..=15_u8 {
        let seed = [byte; 32];
        payload.sol_keys.push(format::SolKeyRecord {
            record_id: [0x40 + byte; 16],
            created_unix: 1,
            seed: Zeroizing::new(seed),
            public: crate::sol::keys::public_key(&seed),
        });
        payload.btc_keys.push(format::BtcKeyRecord {
            record_id: [0x80 + byte; 16],
            created_unix: 1,
            secret: Zeroizing::new([byte; 32]),
            compressed: true,
            network: crate::btc::network::BtcNetwork::Testnet4,
            script: crate::btc::ScriptType::P2tr,
        });
    }
    let encoded = payload.encode().unwrap();
    assert_eq!(encoded.len(), 3_170);
    assert!(encoded.len() + 16 <= usize::try_from(super::PAYLOAD_CT_MAX).unwrap());
    let decoded = Payload::decode(&encoded).unwrap();
    assert_eq!(decoded.record_count(), 46);
    let password = pw(PASSWORD);
    let dek: [u8; 32] = seq(0x20);
    let material = SealMaterial {
        password: &password,
        vault_id: seq(0x01),
        dek: &dek,
        kdf_salt: seq(0x40),
        wrap_nonce: seq(0x50),
        payload_nonce: seq(0x70),
        generation: 1,
        payload: &payload,
    };
    let sealed = format::seal_create_with(&material, &KDF_TEST).unwrap();
    assert_eq!(open_all(&sealed, PASSWORD, &KDF_TEST), Ok(15));
    // A 16th key of one chain is refused by the encoder.
    payload.sol_keys.push(format::SolKeyRecord {
        record_id: [0x3f; 16],
        created_unix: 1,
        seed: Zeroizing::new([0x77; 32]),
        public: crate::sol::keys::public_key(&[0x77; 32]),
    });
    assert_eq!(payload.encode().err(), Some(VaultError::RecordLimit));
}

#[test]
fn key_only_vault_lifecycle() {
    let sol_seed: [u8; 32] = hex::decode_array(SOL_TEST_SEED).unwrap();
    let (storage, mut vault) = empty_vault(KDF_TEST);
    let id = vault
        .create_with_key(&pw(PASSWORD), sol_import(sol_seed), new_slot(), 7)
        .unwrap();
    assert_eq!(
        vault.status(),
        VaultStatus::Unlocked {
            alt_passphrase: false
        }
    );
    assert_eq!(storage.commits(), 1);
    assert_eq!(vault.has_mnemonic(), Ok(false));
    let keys = vault.imported_keys().unwrap();
    assert!(!keys.has_mnemonic && keys.evm.is_empty() && keys.btc.is_empty());
    assert_eq!(
        keys.sol,
        vec![(id, crate::sol::keys::public_key(&sol_seed))]
    );
    // Reload and unlock: straight to Unlocked (no passphrase, no backup step).
    vault.lock();
    let mut vault = reload(&storage);
    assert_eq!(
        vault.unlock(&pw(PASSWORD), new_slot()),
        Ok(VaultStatus::Unlocked {
            alt_passphrase: false
        })
    );
    // Derivation features do not exist.
    assert_eq!(vault.evm_addresses(&[]), Ok(Vec::new()));
    assert_eq!(
        vault.evm_addresses(&[index(0)]).err(),
        Some(VaultError::NoMnemonic)
    );
    assert_eq!(
        vault.evm_address(EvmKeySource::Derived(index(0))).err(),
        Some(VaultError::NoMnemonic)
    );
    assert_eq!(
        vault.reveal_mnemonic(&pw(PASSWORD)).err(),
        Some(VaultError::NoMnemonic)
    );
    assert_eq!(
        vault.btc_account_xpub(BtcCoin::Mainnet).err(),
        Some(VaultError::NoMnemonic)
    );
    assert_eq!(
        vault
            .sol_public_keys(&[crate::slip10::SolKeySource::Standard(index(0))])
            .err(),
        Some(VaultError::NoMnemonic)
    );
    assert_eq!(vault.sol_public_keys(&[]), Ok(Vec::new()));
    assert_eq!(
        vault.backup_challenge().err(),
        Some(VaultError::InvalidState)
    );
    // The imported key signs and reveals.
    let public = crate::sol::keys::public_key(&sol_seed);
    assert_eq!(
        vault.with_imported_ed25519_seed(&public, |seed| Ok(*seed)),
        Ok(sol_seed)
    );
    assert_eq!(
        vault
            .with_imported_ed25519_seed(&[1; 32], |seed| Ok(*seed))
            .err(),
        Some(VaultError::RecordNotFound)
    );
    let (chain, text) = vault.reveal_imported_key(&pw(PASSWORD), id).unwrap();
    assert_eq!(chain, crate::keyimport::ImportChain::Sol);
    let mut pair = sol_seed.to_vec();
    pair.extend_from_slice(&public);
    assert_eq!(text.expose(), crate::codec::base58::encode(&pair));
    assert_eq!(
        vault.reveal_imported_key(&pw(OTHER_PASSWORD), id).err(),
        Some(VaultError::UnlockFailed)
    );
    // Other chains can be added; the last key cannot be removed.
    let evm = vault.import_key(evm_import(7), 8).unwrap();
    assert_eq!(
        vault.remove_imported_key(&pw(PASSWORD), id),
        Ok(crate::keyimport::ImportChain::Sol)
    );
    assert_eq!(
        vault.remove_imported_key(&pw(PASSWORD), evm),
        Err(VaultError::LastKey)
    );
    assert_eq!(
        vault.remove_evm_raw_key(&pw(PASSWORD), evm),
        Err(VaultError::LastKey)
    );
    assert_eq!(vault.imported_keys().unwrap().evm.len(), 1);
    // Creating over an existing vault is refused.
    let (slot, wiped) = slot();
    assert_eq!(
        vault.create_with_key(&pw(PASSWORD), sol_import(sol_seed), slot, 9),
        Err(VaultError::InvalidState)
    );
    assert!(wiped.load(Ordering::SeqCst));
    // Sidecars work as in any vault.
    assert_eq!(vault.save_sidecar(FileKind::Meta, b"{}"), Ok(1));
}

#[test]
#[expect(clippy::too_many_lines, reason = "one table / one scenario")]
fn imported_keys_caps_duplicates_signing_and_removal() {
    use crate::btc::ScriptType;
    use crate::keyimport::ImportChain;
    let (_, mut vault) = imported(None);
    assert_eq!(vault.has_mnemonic(), Ok(true));
    // Solana: 15 per chain, duplicate public key refused.
    let mut sol_ids = Vec::new();
    for byte in 1..=15_u8 {
        sol_ids.push(vault.import_key(sol_import([byte; 32]), 1).unwrap());
    }
    assert_eq!(
        vault.import_key(sol_import([3; 32]), 1),
        Err(VaultError::DuplicateKey)
    );
    assert_eq!(
        vault.import_key(sol_import([0x70; 32]), 1),
        Err(VaultError::RecordLimit)
    );
    // Bitcoin: the cap is separate; the same secret as another script type is allowed, the same
    // use is a duplicate.
    let wif = crate::keyimport::ImportKey::parse(
        crate::keyimport::ImportSpec::Btc(ScriptType::P2wpkh),
        BIP84_TEST_WIF,
    )
    .unwrap();
    let bip84 = vault.import_key(wif, 2).unwrap();
    assert_eq!(
        vault.import_key(
            crate::keyimport::ImportKey::parse(
                crate::keyimport::ImportSpec::Btc(ScriptType::P2wpkh),
                BIP84_TEST_WIF,
            )
            .unwrap(),
            2
        ),
        Err(VaultError::DuplicateKey)
    );
    let taproot = vault
        .import_key(
            crate::keyimport::ImportKey::parse(
                crate::keyimport::ImportSpec::Btc(ScriptType::P2tr),
                BIP84_TEST_WIF,
            )
            .unwrap(),
            2,
        )
        .unwrap();
    for byte in 1..=13_u8 {
        vault
            .import_key(btc_import([byte; 32], true, ScriptType::P2pkh), 3)
            .unwrap();
    }
    assert_eq!(
        vault.import_key(btc_import([0x55; 32], false, ScriptType::P2pkh), 3),
        Err(VaultError::RecordLimit)
    );
    // EVM keeps its own cap of 15 next to full Solana and Bitcoin lists.
    for byte in 1..=15_u8 {
        vault.import_key(evm_import(byte), 4).unwrap();
    }
    assert_eq!(
        vault.import_key(evm_import(0x60), 4),
        Err(VaultError::RecordLimit)
    );
    let keys = vault.imported_keys().unwrap();
    assert_eq!(
        (keys.evm.len(), keys.sol.len(), keys.btc.len()),
        (15, 15, 15)
    );
    let (_, info) = keys.btc.iter().find(|(id, _)| *id == bip84).unwrap();
    assert_eq!(info.address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    assert_eq!(info.script, ScriptType::P2wpkh);
    // The full vault survives lock/unlock (payload ≈ 3.2 KB > the old 2,048-byte bound).
    vault.lock();
    assert_eq!(
        vault.unlock(&pw(PASSWORD), new_slot()),
        Ok(VaultStatus::Unlocked {
            alt_passphrase: false
        })
    );
    assert_eq!(vault.imported_keys().unwrap(), keys);
    // An imported Bitcoin key is lent to the Bitcoin signer with its record's facts (BIP84
    // public key, mainnet, P2WPKH, compressed); an unknown id is `RecordNotFound`.
    {
        use crate::btc::sign::{BtcImportedKeys, BtcKeys, SignError};
        use crate::btc::{BtcKeySource, BtcNetwork, ScriptType};
        let source = BtcKeySource::Imported {
            id: *bip84.as_bytes(),
            script_type: ScriptType::P2wpkh,
            compressed: true,
        };
        let public = vault
            .with_btc_key(BtcNetwork::Mainnet, source, 0, |ctx, secret| {
                Ok(secp256k1::PublicKey::from_secret_key(ctx, secret).serialize())
            })
            .unwrap();
        assert_eq!(
            hex::encode(&public),
            "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
        );
        // The same record used as another network or type is not this account's key.
        for (network, script_type) in [
            (BtcNetwork::Testnet4, ScriptType::P2wpkh),
            (BtcNetwork::Mainnet, ScriptType::P2tr),
        ] {
            let other = BtcKeySource::Imported {
                id: *bip84.as_bytes(),
                script_type,
                compressed: true,
            };
            assert_eq!(
                vault.with_btc_key(network, other, 3, |_, _| Ok(())).err(),
                Some(SignError::KeyMismatch { input: 3 })
            );
        }
        assert_eq!(
            vault.btc_imported_secret(&[0xee; 16]).err(),
            Some(SignError::Vault(VaultError::RecordNotFound))
        );
    }
    // Reveal gives the WIF back; removal works for every chain.
    let (chain, text) = vault.reveal_imported_key(&pw(PASSWORD), bip84).unwrap();
    assert_eq!((chain, text.expose()), (ImportChain::Btc, BIP84_TEST_WIF));
    assert_eq!(
        vault.remove_imported_key(&pw(PASSWORD), taproot),
        Ok(ImportChain::Btc)
    );
    assert_eq!(
        vault.remove_imported_key(&pw(PASSWORD), *sol_ids.first().unwrap()),
        Ok(ImportChain::Sol)
    );
    assert_eq!(
        vault.remove_imported_key(&pw(PASSWORD), taproot),
        Err(VaultError::RecordNotFound)
    );
    // `remove_evm_raw_key` only removes EVM records.
    assert_eq!(
        vault.remove_evm_raw_key(&pw(PASSWORD), bip84),
        Err(VaultError::RecordNotFound)
    );
    let keys = vault.imported_keys().unwrap();
    assert_eq!(
        (keys.evm.len(), keys.sol.len(), keys.btc.len()),
        (15, 14, 14)
    );
}

#[test]
fn backup_pending_refuses_key_import() {
    let (_, mut vault, _) = created();
    assert_eq!(
        vault.import_key(sol_import([1; 32]), 1),
        Err(VaultError::BackupNotConfirmed)
    );
    assert!(vault.imported_keys().unwrap().sol.is_empty());
}

/// Regression (adversarial PoC): a vault written by a NEWER build (same `VAULT_VERSION`, one
/// record of a tag this build does not know) was classified as damage (`PayloadCorrupt` →
/// `Corrupt { prev_available }` → a `.prev` restore that dropped the newer records). It now
/// authenticates and reports `UnsupportedPayload`: the state stays `Locked`, no `.prev` restore
/// is offered or performed, and nothing is quarantined.
#[test]
fn newer_payload_tag_is_unsupported_not_corrupt_and_never_restored_from_prev() {
    let (storage, mut vault) = imported(None);
    vault.import_evm_private_key(&"07".repeat(32), 2).unwrap();
    vault.import_evm_private_key(&"08".repeat(32), 3).unwrap();
    let dek: [u8; 32] = *vault.slot_bytes().unwrap().first_chunk::<32>().unwrap();
    drop(vault);
    let main = storage.main(FileKind::Vault).unwrap();
    let cipher = XChaCha20Poly1305::new_from_slice(&dek).unwrap();
    let mut plain = cipher
        .decrypt(
            XNonce::from_slice(at(&main, 138..162)),
            AeadPayload {
                msg: at(&main, 176..main.len()),
                aad: at(&main, 0..176),
            },
        )
        .unwrap();
    // One more record of a future tag 8 (tag 5 is the hardware key reference, spec/10 §8; tag 6
    // the imported Zcash key, spec/12 §2.3; tag 7 the `PrevDek` block of a DEK rotation, §4.4).
    let count = u16::from_be_bytes(at(&plain, 8..10).try_into().unwrap()) + 1;
    put(&mut plain, 8, &count.to_be_bytes());
    plain.push(8);
    plain.extend_from_slice(&[0x55; 16]);
    plain.extend_from_slice(&[0; 9]);
    let mut header = at(&main, 0..176).to_vec();
    put(
        &mut header,
        162,
        &u32::try_from(plain.len() + 16).unwrap().to_be_bytes(),
    );
    let mut newer = header.clone();
    newer.extend(
        cipher
            .encrypt(
                XNonce::from_slice(at(&header, 138..162)),
                AeadPayload {
                    msg: &plain,
                    aad: &header,
                },
            )
            .unwrap(),
    );
    storage.set_main(FileKind::Vault, Some(newer.clone()));

    let mut vault = reload(&storage);
    assert_eq!(vault.status(), VaultStatus::Locked);
    assert_eq!(
        vault.unlock(&pw(PASSWORD), new_slot()),
        Err(VaultError::UnsupportedPayload)
    );
    assert_eq!(
        vault.status(),
        VaultStatus::Locked,
        "not Corrupt: no .prev offer"
    );
    // A `.prev` recovery attempt from Locked refuses too and leaves the newer file in place.
    assert_eq!(
        vault.recover_from_prev(&pw(PASSWORD), new_slot(), 9),
        Err(VaultError::UnsupportedPayload)
    );
    assert!(storage.quarantined(FileKind::Vault).is_empty());
    assert_eq!(storage.main(FileKind::Vault), Some(newer));
    assert_eq!(vault.quarantined_at(), None);
    // An AEAD failure is still damage.
    let mut damaged = storage.main(FileKind::Vault).unwrap();
    *damaged.last_mut().unwrap() ^= 1;
    storage.set_main(FileKind::Vault, Some(damaged));
    let mut vault = reload(&storage);
    assert_eq!(
        vault.unlock(&pw(PASSWORD), new_slot()),
        Err(VaultError::PayloadCorrupt)
    );
    assert_eq!(
        vault.status(),
        VaultStatus::Corrupt {
            prev_available: true
        }
    );
    vault
        .recover_from_prev(&pw(PASSWORD), new_slot(), 9)
        .unwrap();
    assert_eq!(vault.quarantined_at(), Some(9));
}

// ---- Hardware key references (tag 5, spec/10 §8) ----

/// The slot map of a mock `YubiKey` enrolled with `ABOUT` holding EVM `first`/`first + 1` in
/// SIG/AUT and Solana `first` in PIV 82.
fn hw_record(
    serial: u32,
    first: u32,
    others: &[crate::yubikey::record::HwKeyRecord],
) -> crate::yubikey::record::HwKeyRecord {
    use crate::yubikey::plan::{CardSlot, KeyRole, PgpKey, PivSlot, PlannedSlot};
    let seed = *Mnemonic::parse(ABOUT)
        .unwrap()
        .to_seed(&Bip39Passphrase::empty())
        .unwrap()
        .expose();
    let evm = |i: u32| KeyRole::Evm {
        index: index(i),
        btc: None,
    };
    let plan = [
        PlannedSlot::recommended(CardSlot::OpenPgp(PgpKey::Sig), evm(first)),
        PlannedSlot::recommended(CardSlot::OpenPgp(PgpKey::Aut), evm(first + 1)),
        PlannedSlot::recommended(
            CardSlot::Piv(PivSlot::new(0x82).unwrap()),
            KeyRole::Sol {
                index: index(first),
            },
        ),
    ];
    let mut card = crate::yubikey::mock::MockCard::new(serial);
    let auth = crate::yubikey::enrol::EnrolAuth {
        admin_pin: b"12345678",
        management_key: &crate::yubikey::piv::DEFAULT_MANAGEMENT_KEY,
        piv_pin: b"",
        cipher: Some(&crate::yubikey::mock::ToyCipher),
        challenge: [1; 16],
        overwrite: false,
    };
    crate::yubikey::enrol::enrol_card(
        &mut card,
        crate::yubikey::apdu::ApduMode::Short,
        &seed,
        &plan,
        others,
        &auth,
    )
    .unwrap()
    .record
}

#[test]
#[allow(clippy::indexing_slicing, reason = "test assertions")]
fn hardware_vault_lifecycle() {
    let first = hw_record(11, 0, &[]);
    let (storage, mut vault) = empty_vault(KDF_TEST);
    let id = vault
        .create_with_hardware(&pw(PASSWORD), first.clone(), new_slot(), 5)
        .unwrap();
    assert_eq!(
        vault.status(),
        VaultStatus::Unlocked {
            alt_passphrase: false
        }
    );
    assert_eq!(vault.has_mnemonic(), Ok(false));
    assert_eq!(
        vault.evm_addresses(&[index(0)]),
        Err(VaultError::NoMnemonic)
    );
    // YubiKey EVM accounts answer from the slot map; no vault path lends a key for them.
    assert_eq!(
        vault.evm_address(EvmKeySource::Hardware(index(1))).ok(),
        crate::yubikey::plan::evm_address(&first.slots[1].public).ok()
    );
    assert_eq!(
        vault.evm_address(EvmKeySource::Hardware(index(9))),
        Err(VaultError::RecordNotFound)
    );
    assert_eq!(
        vault.with_secp_key(KeyRef::Evm(EvmKeySource::Hardware(index(0))), |_, _| Ok(())),
        Err(VaultError::RecordNotFound)
    );
    let keys = vault.hardware_keys().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!((keys[0].id, keys[0].created_unix), (id, 5));
    assert_eq!(keys[0].record, first);
    // The payload holds no secret: no Bip39 and no imported-key record.
    let payload = vault.payload().unwrap();
    assert!(payload.bip39.is_empty() && payload.raw_keys.is_empty());
    assert!(payload.sol_keys.is_empty() && payload.btc_keys.is_empty());

    // A second card with other indices, then the same serial again.
    let second = hw_record(12, 2, std::slice::from_ref(&first));
    let second_id = vault.add_hardware_key(second.clone(), 6).unwrap();
    assert_eq!(
        vault.add_hardware_key(second.clone(), 7),
        Err(VaultError::DuplicateKey)
    );
    // A record contradicting the first (same path, other public key) is refused.
    let mut forged = hw_record(13, 4, &[first.clone(), second.clone()]);
    forged.slots[0].role = first.slots[0].role;
    assert_eq!(
        vault.add_hardware_key(forged, 8),
        Err(VaultError::Key(KeyError::DerivationFailed))
    );

    // Reload and unlock: the slot map survives byte for byte.
    vault.lock();
    let mut vault = reload(&storage);
    vault.unlock(&pw(PASSWORD), new_slot()).unwrap();
    let keys = vault.hardware_keys().unwrap();
    assert_eq!(
        keys.iter()
            .map(|key| key.record.clone())
            .collect::<Vec<_>>(),
        vec![first.clone(), second]
    );
    // Imported keys can live next to hardware keys.
    vault.import_evm_private_key(&"07".repeat(32), 9).unwrap();

    // Removal needs the password; the last record of a vault without words stays.
    assert_eq!(
        vault.remove_hardware_key(&pw(OTHER_PASSWORD), second_id),
        Err(VaultError::UnlockFailed)
    );
    vault.remove_hardware_key(&pw(PASSWORD), second_id).unwrap();
    assert_eq!(
        vault.remove_hardware_key(&pw(PASSWORD), second_id),
        Err(VaultError::RecordNotFound)
    );
    let raw = vault.raw_keys().unwrap()[0].0;
    vault.remove_imported_key(&pw(PASSWORD), raw).unwrap();
    assert_eq!(
        vault.remove_hardware_key(&pw(PASSWORD), id),
        Err(VaultError::LastKey)
    );
    assert_eq!(vault.hardware_keys().unwrap().len(), 1);
}

#[test]
#[allow(clippy::indexing_slicing, reason = "test assertions")]
fn hardware_keys_next_to_a_mnemonic_and_the_largest_payload() {
    use crate::yubikey::plan::{CardSlot, KeyRole, PinPolicy, PivSlot, TouchPolicy};
    use crate::yubikey::record::{HwKeyRecord, HwPublicKey, RecordedSlot};

    let (_, mut vault) = imported(None);
    let record = hw_record(21, 0, &[]);
    vault.add_hardware_key(record.clone(), 1).unwrap();
    assert_eq!(vault.hardware_keys().unwrap()[0].record, record);

    // 24 words + 15 keys of each chain + 8 cards × 24 slots fits PAYLOAD_CT_MAX.
    let mut payload = golden_payload();
    payload.raw_keys.extend((1..=15).map(raw_record));
    for card in 0..8_u32 {
        let slots = (0..20_u8)
            .map(|n| PivSlot::retired(n).unwrap().id())
            .chain(PivSlot::STANDARD)
            .enumerate()
            .map(|(position, id)| {
                let i = card * 24 + u32::try_from(position).unwrap();
                let seed = [u8::try_from(i % 250).unwrap() + 1; 32];
                RecordedSlot {
                    slot: CardSlot::Piv(PivSlot::new(id).unwrap()),
                    role: KeyRole::Sol { index: index(i) },
                    touch: TouchPolicy::Always,
                    pin: PinPolicy::Always,
                    public: HwPublicKey::Ed25519(crate::sol::keys::public_key(&seed)),
                    path_known: true,
                }
            })
            .collect();
        payload.hw_keys.push(format::HwKeyEntry {
            record_id: [0xC0 + u8::try_from(card).unwrap(); 16],
            created_unix: 1,
            record: HwKeyRecord {
                serial: 1_000 + card,
                firmware: crate::yubikey::Firmware::new(5, 7, 4),
                fingerprint: [1, 2, 3, 4],
                slots,
            },
        });
    }
    let encoded = payload.encode().unwrap();
    assert_eq!(encoded.len(), 16 + 64 + 15 * 57 + 8 * (25 + 12 + 24 * 48));
    assert!(encoded.len() + 16 <= usize::try_from(super::PAYLOAD_CT_MAX).unwrap());
    let decoded = Payload::decode(&encoded).unwrap();
    assert_eq!(decoded.hw_keys, payload.hw_keys);
    // A ninth card is over the limit.
    let mut ninth = payload.hw_keys[0].clone();
    ninth.record_id = [0xEE; 16];
    ninth.record.serial = 9_999;
    payload.hw_keys.push(ninth);
    assert_eq!(payload.encode().err(), Some(VaultError::RecordLimit));
}

/// spec/08 §3.5: the public key and the WIF export of a Bitcoin account on EVM account `i`'s key
/// (`m/44'/60'/0'/0/i`, compressed, the network's version byte, after the password); the EVM
/// private key of `abandon`×11 `about` account 0 is the well-known `1ab42cc4…b727`.
#[test]
fn evm_shared_public_key_and_wif() {
    use crate::btc::BtcNetwork;
    let vault = unlocked_with(ABOUT);
    let zero = AccountIndex::ZERO;
    assert_eq!(
        hex::encode(&vault.evm_public_key(zero).unwrap()),
        "0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299"
    );
    for network in [BtcNetwork::Mainnet, BtcNetwork::Testnet4] {
        let wif = vault
            .reveal_evm_shared_wif(&pw(PASSWORD), zero, network)
            .unwrap();
        let parsed = crate::codec::wif::parse_wif(wif.expose()).unwrap();
        assert!(parsed.compressed());
        assert_eq!(parsed.network(), network);
        assert_eq!(
            hex::encode(parsed.secret().as_slice()),
            "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"
        );
        // The same secret as the EVM export.
        let evm = vault
            .reveal_evm_private_key(&pw(PASSWORD), EvmKeySource::Derived(zero))
            .unwrap();
        assert_eq!(hex::encode(parsed.secret().as_slice()), evm.expose());
    }
    assert_eq!(
        vault
            .reveal_evm_shared_wif(&pw(OTHER_PASSWORD), zero, BtcNetwork::Mainnet)
            .err(),
        Some(VaultError::UnlockFailed)
    );
}

// ---- Keys connected without recovery words (tag 5 unknown path, spec/10 §7.6) and imported
// ---- Zcash keys (tag 6, spec/12 §2.3) ----

/// Secret 1 (`G`): compressed WIF and Zcash P2PKH addresses computed independently (Python
/// base58check over `HASH160(02 79BE…)` = `751e76e8…`, versions `1CB8` / `1D25`).
const ONE_WIF_MAIN: &str = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
const ONE_WIF_TEST: &str = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";
const ONE_T1: &str = "t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs";
const ONE_TM: &str = "tmLPctKo9j49rtCSKpwEBpLBeykiTGomGQs";
const G_COMPRESSED: [u8; 33] = [
    0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
    0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
    0x98,
];

fn zec_key(
    network: crate::zec::ZecNetwork,
    text: &str,
) -> Result<crate::keyimport::ImportKey, KeyError> {
    crate::keyimport::ImportKey::parse(crate::keyimport::ImportSpec::Zec(network), text)
}

#[test]
#[allow(
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "test assertions of one scenario"
)]
fn zcash_wif_import_reveal_sign_and_refusals() {
    use crate::keyimport::{ImportChain, ImportPreview};
    use crate::zec::ZecNetwork::{Mainnet, Testnet};

    // Parse vectors: compressed WIF of the tab's network, or 64 hex with the network.
    let preview = |network, text: &str| match zec_key(network, text).unwrap().preview().unwrap() {
        ImportPreview::Zec(info) => info,
        other => unreachable!("not a Zcash preview: {other:?}"),
    };
    let main = preview(Mainnet, ONE_WIF_MAIN);
    assert_eq!((main.address.as_str(), main.pubkey), (ONE_T1, G_COMPRESSED));
    assert_eq!(preview(Testnet, ONE_WIF_TEST).address, ONE_TM);
    let hex = format!("{:064x}", 1);
    assert_eq!(preview(Testnet, &format!("0x{hex}")).address, ONE_TM);
    assert_eq!(preview(Mainnet, &hex.to_uppercase()).address, ONE_T1);
    assert_eq!(
        zec_key(Testnet, ONE_WIF_MAIN).err(),
        Some(KeyError::ZecKeyNetwork)
    );
    for bad in [
        "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf", // uncompressed
        "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWo", // checksum
        &"0".repeat(64),                                       // zero scalar
        "t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs",                 // an address
    ] {
        assert_eq!(
            zec_key(Mainnet, bad).err(),
            Some(KeyError::ZecKeyFormat),
            "{bad}"
        );
    }

    // Vault: import, duplicate refused, the same secret on the other network is another key.
    let (storage, mut vault) = imported(None);
    let id = vault
        .import_key(zec_key(Mainnet, ONE_WIF_MAIN).unwrap(), 4)
        .unwrap();
    assert_eq!(
        vault.import_key(zec_key(Mainnet, &hex).unwrap(), 5),
        Err(VaultError::DuplicateKey)
    );
    let test_id = vault
        .import_key(zec_key(Testnet, ONE_WIF_TEST).unwrap(), 6)
        .unwrap();
    // The standard derived key of the wallet is refused (it already is a Zcash address).
    let derived = vault
        .with_secp_key(
            KeyRef::Zec {
                mnemonic: None,
                test: false,
                account: 0,
                index: 0,
            },
            |_, secret| Ok(crate::hex::encode(&secret.secret_bytes())),
        )
        .unwrap();
    assert_eq!(
        vault.import_key(zec_key(Mainnet, &derived).unwrap(), 7),
        Err(VaultError::DuplicateKey)
    );
    // Cap 15 per chain.
    for n in 2..=14_u8 {
        vault
            .import_key(zec_key(Mainnet, &format!("{n:064x}")).unwrap(), 8)
            .unwrap();
    }
    assert_eq!(
        vault.import_key(zec_key(Mainnet, &format!("{:064x}", 99)).unwrap(), 9),
        Err(VaultError::RecordLimit)
    );
    // Reload: the records survive; listing, signing key and reveal.
    vault.lock();
    let mut vault = reload(&storage);
    vault.unlock(&pw(PASSWORD), new_slot()).unwrap();
    let keys = vault.imported_keys().unwrap();
    assert_eq!(keys.zec.len(), 15);
    assert_eq!(
        (keys.zec[0].0, keys.zec[0].1.address.as_str()),
        (id, ONE_T1)
    );
    assert_eq!(keys.zec[1].1.address, ONE_TM);
    let lent = vault
        .with_secp_key(
            KeyRef::ZecImported {
                network: Mainnet,
                pubkey: G_COMPRESSED,
            },
            |ctx, secret| Ok(secp256k1::PublicKey::from_secret_key(ctx, secret).serialize()),
        )
        .unwrap();
    assert_eq!(lent, G_COMPRESSED);
    assert!(
        vault
            .with_secp_key(
                KeyRef::ZecImported {
                    network: Mainnet,
                    pubkey: [2; 33],
                },
                |_, _| Ok(()),
            )
            .is_err()
    );
    let (chain, wif) = vault.reveal_imported_key(&pw(PASSWORD), id).unwrap();
    assert_eq!((chain, wif.expose()), (ImportChain::Zec, ONE_WIF_MAIN));
    let (_, wif) = vault.reveal_imported_key(&pw(PASSWORD), test_id).unwrap();
    assert_eq!(wif.expose(), ONE_WIF_TEST);
    assert_eq!(
        vault.remove_imported_key(&pw(PASSWORD), test_id),
        Ok(ImportChain::Zec)
    );
    // The payload names the record tag 6, which builds before it refuse (unknown tag →
    // UnsupportedPayload, `newer_payload_tag_is_unsupported_not_corrupt…`).
    let payload = vault.payload().unwrap();
    let encoded = payload.encode().unwrap();
    assert_eq!(payload.zec_keys.len(), 14);
    let first_zec = encoded.len() - 14 * 58;
    assert_eq!(encoded[first_zec], 6);
}

#[test]
#[allow(clippy::indexing_slicing, reason = "test assertions")]
fn unknown_path_card_vault_accounts_and_zcash_collision() {
    use crate::btc::account::{HwBtcKey, ScriptType};
    use crate::yubikey::plan::{CardSlot, KeyRole, PgpKey, PinPolicy, PivSlot, TouchPolicy};
    use crate::yubikey::record::{HwKeyRecord, HwPublicKey, RecordedSlot};

    let slot = |slot, role, public| RecordedSlot {
        slot,
        role,
        touch: TouchPolicy::Always,
        pin: if matches!(slot, CardSlot::Piv(_)) {
            PinPolicy::Always
        } else {
            PinPolicy::NotApplicable
        },
        public,
        path_known: false,
    };
    let sol_public = crate::sol::keys::public_key(&[3; 32]);
    let record = HwKeyRecord {
        serial: 41,
        firmware: crate::yubikey::Firmware::new(5, 7, 4),
        fingerprint: [0; 4],
        slots: vec![
            slot(
                CardSlot::OpenPgp(PgpKey::Sig),
                KeyRole::Evm {
                    index: index(900),
                    btc: None,
                },
                HwPublicKey::Secp256k1(G_COMPRESSED),
            ),
            slot(
                CardSlot::OpenPgp(PgpKey::Aut),
                KeyRole::Btc {
                    network: crate::btc::BtcNetwork::Testnet4,
                    script: ScriptType::P2shP2wpkh,
                    index: 900,
                },
                hw_record(1, 0, &[]).slots[0].public,
            ),
            slot(
                CardSlot::Piv(PivSlot::new(0x82).unwrap()),
                KeyRole::Sol { index: index(900) },
                HwPublicKey::Ed25519(sol_public),
            ),
        ],
    };
    let (storage, mut vault) = empty_vault(KDF_TEST);
    vault
        .create_with_hardware(&pw(PASSWORD), record.clone(), new_slot(), 1)
        .unwrap();
    vault.lock();
    let mut vault = reload(&storage);
    vault.unlock(&pw(PASSWORD), new_slot()).unwrap();
    assert_eq!(vault.hardware_keys().unwrap()[0].record, record);
    // The accounts answer from the slot map exactly like enrolled ones.
    assert_eq!(
        vault.evm_address(EvmKeySource::Hardware(index(900))).ok(),
        crate::yubikey::plan::evm_address(&record.slots[0].public).ok()
    );
    assert_eq!(
        vault
            .sol_public_keys(&[crate::slip10::SolKeySource::Hardware(index(900))])
            .unwrap(),
        vec![sol_public]
    );
    let btc = vault
        .hardware_btc_account(
            crate::btc::BtcNetwork::Testnet4,
            ScriptType::P2shP2wpkh,
            HwBtcKey::Address(900),
        )
        .unwrap();
    assert!(
        btc.path_text_in(
            crate::lang::Lang::Ko,
            crate::btc::BtcNetwork::Testnet4,
            crate::bip32::path::BtcChain::Receive,
            0
        )
        .starts_with(crate::yubikey::plan::T_UNKNOWN_PATH)
    );
    assert!(
        crate::slip10::SolKeySource::Hardware(index(900))
            .path_text_in(crate::lang::Lang::Ko)
            .starts_with(crate::yubikey::plan::T_UNKNOWN_PATH)
    );
    // A Zcash key that a card holds is refused; another one is imported next to the card.
    assert_eq!(
        vault.import_key(
            zec_key(crate::zec::ZecNetwork::Mainnet, ONE_WIF_MAIN).unwrap(),
            2
        ),
        Err(VaultError::DuplicateKey)
    );
    vault
        .import_key(
            zec_key(crate::zec::ZecNetwork::Mainnet, &format!("{:064x}", 2)).unwrap(),
            3,
        )
        .unwrap();
    // A mnemonic card can join later: the unknown-path record takes no part in the fingerprint
    // rule.
    let enrolled = hw_record(42, 0, std::slice::from_ref(&record));
    vault.add_hardware_key(enrolled, 4).unwrap();
}

// ---------------------------------------------------------------- several mnemonics (§8.6)

/// Hardhat/Anvil's published default mnemonic: account 0 `0xf39F…2266`, account 1 `0x7099…79C8`.
pub(crate) const HARDHAT: &str = "test test test test test test test test test test test junk";

fn evm_text(vault: &Vault, src: EvmKeySource) -> String {
    vault.evm_address(src).unwrap().to_checksum()
}

#[test]
fn several_mnemonics_round_trip_derive_and_ask_each_passphrase() {
    let (storage, mut vault) = imported(None);
    let primary = vault.mnemonics().unwrap().first().unwrap().id;
    let second = vault.add_mnemonic(&pw(PASSWORD), HARDHAT, None, 2).unwrap();
    // The same seed again is refused; the same words with a passphrase are another wallet.
    assert_eq!(
        vault.add_mnemonic(&pw(PASSWORD), ABOUT, None, 3),
        Err(VaultError::DuplicateKey)
    );
    let third = vault
        .add_mnemonic(
            &pw(PASSWORD),
            ABOUT,
            Some(Bip39Passphrase::new("TREZOR").unwrap()),
            4,
        )
        .unwrap();
    let check = |vault: &Vault| {
        assert_eq!(
            evm_text(vault, EvmKeySource::Derived(index(0))),
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
        assert_eq!(
            evm_text(vault, EvmKeySource::Mnemonic(primary, index(0))),
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
        assert_eq!(
            vault
                .evm_addresses_of(second, &[index(0), index(1)])
                .unwrap()
                .iter()
                .map(|address| address.to_checksum())
                .collect::<Vec<_>>(),
            [
                "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
                "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
            ]
        );
        assert_eq!(
            evm_text(vault, EvmKeySource::Mnemonic(third, index(0))),
            "0x9c32F71D4DB8Fb9e1A58B0a80dF79935e7256FA6"
        );
    };
    check(&vault);
    let infos = vault.mnemonics().unwrap();
    assert_eq!(
        infos
            .iter()
            .map(|info| (
                info.id,
                info.primary,
                info.passphrase_used,
                info.backup_confirmed
            ))
            .collect::<Vec<_>>(),
        [
            (primary, true, false, true),
            (second, false, false, true),
            (third, false, true, true)
        ]
    );
    // Reopened from disk: the third mnemonic's passphrase is asked for (position 3 of 3).
    vault.lock();
    let mut vault = reload(&storage);
    assert_eq!(
        vault.unlock(&pw(PASSWORD), new_slot()),
        Ok(VaultStatus::PassphraseRequired)
    );
    let pending = vault.pending_passphrase().unwrap();
    assert_eq!((pending.id, pending.position, pending.count), (third, 3, 3));
    assert_eq!(
        vault.enter_passphrase(Bip39Passphrase::new("TREZOR").unwrap()),
        Ok(VaultStatus::Unlocked {
            alt_passphrase: false
        })
    );
    check(&vault);
}

#[test]
fn added_mnemonic_backup_gates_signing_and_removal_rules() {
    let (_, mut vault) = imported(None);
    let primary = vault.mnemonics().unwrap().first().unwrap().id;
    let (id, phrase) = vault.generate_mnemonic(&pw(PASSWORD), 2).unwrap();
    let key = KeyRef::Evm(EvmKeySource::Mnemonic(id, index(0)));
    // Receiving works, signing waits for the quiz; the wallet itself stays unlocked.
    assert!(
        vault
            .evm_address(EvmKeySource::Mnemonic(id, index(0)))
            .is_ok()
    );
    assert_eq!(
        vault.with_secp_key(key, |_, _| Ok(())),
        Err(VaultError::BackupNotConfirmed)
    );
    assert!(
        vault
            .with_secp_key(KeyRef::Evm(EvmKeySource::Derived(index(0))), |_, _| Ok(()))
            .is_ok()
    );
    let challenge = vault.backup_challenge_for(id).unwrap();
    vault
        .confirm_backup_for(
            id,
            challenge.id,
            refs(&answers(phrase.expose(), challenge.positions)),
        )
        .unwrap();
    assert!(vault.with_secp_key(key, |_, _| Ok(())).is_ok());
    assert_eq!(
        vault.remove_mnemonic(&pw(PASSWORD), primary),
        Err(VaultError::PrimaryMnemonic)
    );
    vault.remove_mnemonic(&pw(PASSWORD), id).unwrap();
    assert_eq!(
        vault
            .evm_address(EvmKeySource::Mnemonic(id, index(0)))
            .err(),
        Some(VaultError::RecordNotFound)
    );
    assert_eq!(vault.mnemonics().unwrap().len(), 1);
}

/// Independently computed (Node.js `crypto`: PBKDF2-HMAC-SHA512, SLIP-0010 / BIP32 by hand,
/// Ed25519 from PKCS#8, RIPEMD-160, bech32 / base58check by hand; the same script gives the
/// published Hardhat account 0 key `ac0974be…ff80`) addresses of the Hardhat mnemonic.
pub(crate) const HARDHAT_SOL_0: &str = "oeYf6KAJkLYhBuR8CiGc6L4D4Xtfepr85fuDgA9kq96";
pub(crate) const HARDHAT_SOL_1: &str = "AqynRZwvVqUPRwRJXvm6odUb3t93fDjnWe3p6BeuUFxD";
pub(crate) const HARDHAT_BIP84_MAIN: &str = "bc1q4qw42stdzjqs59xvlrlxr8526e3nunw7mp73te";
pub(crate) const HARDHAT_BIP84_TEST: &str = "tb1qquv9lg5g2r4jkr0ahun0ddfg5xntxjelvmc7t8";
pub(crate) const HARDHAT_ZEC_MAIN: &str = "t1UxWM2wcKHaLeLo7rN6ivUp4CtsdqSwQh8";
pub(crate) const HARDHAT_ZEC_TEST: &str = "tmVCXaxV1ZfbyshJLjD7YqVtZf95rgFWJj7";

#[test]
fn added_mnemonic_derives_solana_bitcoin_and_zcash_keys() {
    use crate::bip32::path::BtcPurpose;
    use crate::btc::{BtcAccountKey, BtcNetwork, ScriptType};
    use crate::slip10::SolKeySource;
    let (_, mut vault) = imported(None);
    let second = vault.add_mnemonic(&pw(PASSWORD), HARDHAT, None, 2).unwrap();
    // Solana m/44'/501'/i'/0' of the added mnemonic; the primary standard path is unchanged.
    let keys = vault
        .sol_public_keys(&[
            SolKeySource::Mnemonic(second, index(0)),
            SolKeySource::Mnemonic(second, index(1)),
            SolKeySource::Standard(index(0)),
        ])
        .unwrap();
    let base58 = |key: &[u8; 32]| crate::sol::SolAddress::from_bytes(*key).to_base58();
    let [added0, added1, primary0]: [[u8; 32]; 3] = keys.try_into().unwrap();
    let (added0, added1, primary0) = (&added0, &added1, &primary0);
    assert_eq!(base58(added0), HARDHAT_SOL_0);
    assert_eq!(base58(added1), HARDHAT_SOL_1);
    assert_eq!(
        vault
            .sol_public_keys(&[SolKeySource::Standard(index(0))])
            .unwrap()
            .as_slice(),
        [*primary0]
    );
    assert_ne!(added0, primary0);
    // Bitcoin BIP84 first address (mainnet and testnet4) from the account node, and the same
    // public key by private derivation (the signer's key).
    for (network, test, expected) in [
        (BtcNetwork::Mainnet, false, HARDHAT_BIP84_MAIN),
        (BtcNetwork::Testnet4, true, HARDHAT_BIP84_TEST),
    ] {
        let coin = BtcCoin::new(test, BtcPurpose::Bip84, 0).unwrap();
        let xpub = vault.btc_account_xpub_of(Some(second), coin).unwrap();
        assert_ne!(xpub, vault.btc_account_xpub(coin).unwrap());
        let account = BtcAccountKey::hd(ScriptType::P2wpkh, 0, xpub)
            .unwrap()
            .with_mnemonic(Some(second));
        assert_eq!(
            account
                .address(network, BtcChain::Receive, 0)
                .unwrap()
                .to_string(),
            expected
        );
        let public = vault
            .with_secp_key(
                KeyRef::Btc {
                    mnemonic: Some(second),
                    coin,
                    chain: BtcChain::Receive,
                    index: 0,
                },
                |ctx, secret| Ok(secp256k1::PublicKey::from_secret_key(ctx, secret).serialize()),
            )
            .unwrap();
        assert_eq!(
            crate::btc::address::hash160(&public),
            crate::btc::address::hash160(
                &crate::bip32::derive_public_child(
                    &crate::bip32::derive_public_child(&xpub, 0).unwrap(),
                    0
                )
                .unwrap()
                .pubkey
            )
        );
    }
    // Zcash m/44'/{133|1}'/0'/0/0.
    for (network, expected) in [
        (crate::zec::ZecNetwork::Mainnet, HARDHAT_ZEC_MAIN),
        (crate::zec::ZecNetwork::Testnet, HARDHAT_ZEC_TEST),
    ] {
        let test = network == crate::zec::ZecNetwork::Testnet;
        let pubkey = vault.zec_public_key_of(Some(second), test, 0, 0).unwrap();
        assert_ne!(pubkey, vault.zec_public_key(test, 0, 0).unwrap());
        let account = crate::zec::ZecAccount {
            network,
            source: crate::zec::ZecKeySource::Mnemonic {
                mnemonic: second,
                account: 0,
                index: 0,
            },
            pubkey,
        };
        assert_eq!(account.address(), expected);
    }
    // An unknown mnemonic id is refused.
    let unknown = RecordId::from_bytes([0x5a; 16]);
    assert_eq!(
        vault.sol_public_keys(&[SolKeySource::Mnemonic(unknown, index(0))]),
        Err(VaultError::RecordNotFound)
    );
    assert_eq!(
        vault.zec_public_key_of(Some(unknown), false, 0, 0),
        Err(VaultError::RecordNotFound)
    );
}

#[test]
fn added_mnemonic_backup_gates_solana_bitcoin_and_zcash_signing() {
    use crate::bip32::path::BtcPurpose;
    use crate::slip10::SolKeySource;
    let (_, mut vault) = imported(None);
    let (id, phrase) = vault.generate_mnemonic(&pw(PASSWORD), 2).unwrap();
    let sol = SolKeySource::Mnemonic(id, index(0));
    let btc = KeyRef::Btc {
        mnemonic: Some(id),
        coin: BtcCoin::new(false, BtcPurpose::Bip86, 3).unwrap(),
        chain: BtcChain::Change,
        index: 7,
    };
    let zec = KeyRef::Zec {
        mnemonic: Some(id),
        test: true,
        account: 0,
        index: 0,
    };
    // Public keys (receiving) work; every signing path waits for that mnemonic's quiz.
    assert!(vault.sol_public_keys(&[sol]).is_ok());
    assert!(vault.zec_public_key_of(Some(id), true, 0, 0).is_ok());
    assert_eq!(
        vault.with_ed25519_seed(sol, |_| Ok(())),
        Err(VaultError::BackupNotConfirmed)
    );
    assert_eq!(
        vault.with_secp_key(btc, |_, _| Ok(())),
        Err(VaultError::BackupNotConfirmed)
    );
    assert_eq!(
        vault.with_secp_key(zec, |_, _| Ok(())),
        Err(VaultError::BackupNotConfirmed)
    );
    // The primary mnemonic's keys are not gated by it.
    assert!(
        vault
            .with_ed25519_seed(SolKeySource::Standard(index(0)), |_| Ok(()))
            .is_ok()
    );
    let challenge = vault.backup_challenge_for(id).unwrap();
    vault
        .confirm_backup_for(
            id,
            challenge.id,
            refs(&answers(phrase.expose(), challenge.positions)),
        )
        .unwrap();
    assert!(vault.with_ed25519_seed(sol, |_| Ok(())).is_ok());
    assert!(vault.with_secp_key(btc, |_, _| Ok(())).is_ok());
    assert!(vault.with_secp_key(zec, |_, _| Ok(())).is_ok());
}

/// spec/02 §7.5, §8.6: a session that continued with a mismatched passphrase adds (its duplicate
/// check would see the other-passphrase seed), makes and removes no recovery phrase.
#[test]
fn alt_passphrase_session_changes_no_recovery_phrase() {
    let (storage, mut vault) = imported(Some("TREZOR"));
    vault.lock();
    vault.unlock(&pw(PASSWORD), new_slot()).unwrap();
    assert_eq!(
        vault.enter_passphrase(Bip39Passphrase::new("trezor").unwrap()),
        Ok(VaultStatus::PassphraseMismatch)
    );
    vault.accept_mismatched_passphrase().unwrap();
    assert_eq!(
        vault.add_mnemonic(&pw(PASSWORD), HARDHAT, None, 2),
        Err(VaultError::InvalidState)
    );
    assert_eq!(
        vault.generate_mnemonic(&pw(PASSWORD), 2).err(),
        Some(VaultError::InvalidState)
    );
    let primary = vault.mnemonics().unwrap().first().unwrap().id;
    assert_eq!(
        vault.remove_mnemonic(&pw(PASSWORD), primary),
        Err(VaultError::InvalidState)
    );
    assert_eq!(storage.commits(), 1);
}

/// A key-only vault's first phrase from "새 복구 단어 만들기" is its primary one with the quiz
/// open: the next unlock is `Unlocked`, not `BackupPending` (the imported key keeps signing),
/// and only the phrase's own keys wait for its quiz, which runs in the unlocked session.
#[test]
fn key_only_vault_first_phrase_gates_only_its_own_keys() {
    let (storage, mut vault) = empty_vault(KDF_TEST);
    let raw = vault
        .create_with_key(&pw(PASSWORD), evm_import(7), new_slot(), 1)
        .unwrap();
    let (id, phrase) = vault.generate_mnemonic(&pw(PASSWORD), 2).unwrap();
    assert!(
        vault
            .mnemonics()
            .unwrap()
            .first()
            .is_some_and(|info| info.id == id && info.primary && !info.backup_confirmed)
    );
    vault.lock();
    let mut vault = reload(&storage);
    assert_eq!(
        vault.unlock(&pw(PASSWORD), new_slot()),
        Ok(VaultStatus::Unlocked {
            alt_passphrase: false
        })
    );
    let imported = KeyRef::Evm(EvmKeySource::Raw(raw));
    let derived = KeyRef::Evm(EvmKeySource::Derived(index(0)));
    assert!(vault.with_secp_key(imported, |_, _| Ok(())).is_ok());
    assert_eq!(
        vault.with_secp_key(derived, |_, _| Ok(())),
        Err(VaultError::BackupNotConfirmed)
    );
    let challenge = vault.backup_challenge_for(id).unwrap();
    vault
        .confirm_backup_for(
            id,
            challenge.id,
            refs(&answers(phrase.expose(), challenge.positions)),
        )
        .unwrap();
    assert!(vault.with_secp_key(derived, |_, _| Ok(())).is_ok());
}
