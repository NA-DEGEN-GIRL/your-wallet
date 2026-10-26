//! vault v3 byte formats: header, KDF, DEK wrap, payload codec, sidecar envelopes
//! (spec/02 §4.2–§4.6, §5.1–§5.2). All integers are big-endian.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use secp256k1::SecretKey;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::{
    FileKind, HKDF_KEK_INFO, HKDF_KEK_SALT, JOURNAL_MAGIC, JOURNAL_MAX_PLAINTEXT,
    KDF_ID_ARGON2ID_V13, KDF_V3, KEY_BLOCK_END, KEY_SECTION_END, KdfParams, MAX_RECORDS,
    META_MAGIC, META_MAX_PLAINTEXT, PAYLOAD_CT_MAX, PAYLOAD_CT_MIN, SIDECAR_HEADER_LEN,
    VAULT_HEADER_LEN, VAULT_MAGIC, VAULT_VERSION, WRAPPED_DEK_LEN,
};
use crate::bip39::Mnemonic;
use crate::error::{KeyError, StorageError, VaultError};
use crate::password::VaultPassword;

/// Payload plaintext magic.
pub(crate) const PAYLOAD_MAGIC: [u8; 8] = *b"YWPAY003";
pub(crate) const MAX_RAW_KEYS: usize = MAX_RECORDS - 1;
const TAG_LEN: usize = 16;
const PAYLOAD_HEADER_LEN: usize = 16;
const BIP39_RECORD_FIXED_LEN: usize = 32;
const RAW_RECORD_LEN: usize = 57;
const TAG_BIP39: u8 = 1;
const TAG_RAW_KEY: u8 = 2;
const SIDECAR_VERSION: u16 = 3;
const HKDF_META_INFO: &[u8] = b"your-wallet/v3/meta";
const HKDF_JOURNAL_INFO: &[u8] = b"your-wallet/v3/journal";
const INTERNAL: VaultError = VaultError::Key(KeyError::Internal);

#[cfg(test)]
thread_local! {
    /// Argon2 invocations on this thread (tests assert which paths run the KDF).
    pub(crate) static KDF_CALLS: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
    /// When set, the next sealed vault is corrupted before its self-check (spec/02 §11.6).
    pub(crate) static CORRUPT_NEXT_SEAL: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

#[cfg(test)]
fn inject_corruption(bytes: &mut [u8]) {
    if CORRUPT_NEXT_SEAL.with(|flag| flag.replace(false))
        && let Some(last) = bytes.last_mut()
    {
        *last ^= 1;
    }
}

#[cfg(not(test))]
const fn inject_corruption(_bytes: &mut [u8]) {}

/// Bounds-checked big-endian reader (archive `Cursor` pattern).
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.bytes.split_first_chunk::<N>()?;
        self.bytes = rest;
        Some(*head)
    }

    fn slice(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.bytes.split_at_checked(len)?;
        self.bytes = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(|[byte]| byte)
    }

    fn u16(&mut self) -> Option<u16> {
        self.array().map(u16::from_be_bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_be_bytes)
    }

    fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_be_bytes)
    }

    const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Parsed vault header fields that vary between files.
#[derive(Clone, Copy)]
pub(crate) struct Header {
    pub(crate) vault_id: [u8; 16],
    pub(crate) kdf_salt: [u8; 16],
    pub(crate) wrap_nonce: [u8; 24],
    pub(crate) wrapped_dek: [u8; WRAPPED_DEK_LEN],
    pub(crate) generation: u64,
    pub(crate) payload_nonce: [u8; 24],
    pub(crate) payload_ct_len: u32,
}

/// `header[0..82]`: the DEK wrap AAD.
fn key_block(
    vault_id: &[u8; 16],
    params: &KdfParams,
    kdf_salt: &[u8; 16],
    wrap_nonce: &[u8; 24],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(KEY_BLOCK_END);
    out.extend_from_slice(&VAULT_MAGIC);
    out.extend_from_slice(&VAULT_VERSION.to_be_bytes());
    out.extend_from_slice(&u16::try_from(VAULT_HEADER_LEN).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(vault_id);
    out.extend_from_slice(&KDF_ID_ARGON2ID_V13.to_be_bytes());
    out.extend_from_slice(&params.m_kib.to_be_bytes());
    out.extend_from_slice(&params.t.to_be_bytes());
    out.extend_from_slice(&params.p.to_be_bytes());
    out.extend_from_slice(kdf_salt);
    out.extend_from_slice(wrap_nonce);
    out
}

fn encode_header(
    header: &Header,
    params: &KdfParams,
) -> Result<[u8; VAULT_HEADER_LEN], VaultError> {
    let mut out = key_block(
        &header.vault_id,
        params,
        &header.kdf_salt,
        &header.wrap_nonce,
    );
    out.reserve_exact(VAULT_HEADER_LEN - KEY_BLOCK_END);
    out.extend_from_slice(&header.wrapped_dek);
    out.extend_from_slice(&header.generation.to_be_bytes());
    out.extend_from_slice(&header.payload_nonce);
    out.extend_from_slice(&header.payload_ct_len.to_be_bytes());
    out.extend_from_slice(&0_u32.to_be_bytes());
    out.extend_from_slice(&[0_u8; 6]);
    <[u8; VAULT_HEADER_LEN]>::try_from(out.as_slice()).map_err(|_| INTERNAL)
}

/// Structural decode, steps 1–7 of spec/02 §4.5 (no KDF).
pub(crate) fn decode_header(bytes: &[u8], params: &KdfParams) -> Result<Header, VaultError> {
    let head = bytes
        .first_chunk::<VAULT_HEADER_LEN>()
        .ok_or(VaultError::Malformed)?;
    let mut reader = Reader::new(head);
    let mut read = || -> Option<_> {
        Some((
            reader.array::<8>()?,
            reader.u16()?,
            reader.u16()?,
            reader.array::<16>()?,
            reader.u16()?,
            [reader.u32()?, reader.u32()?, reader.u32()?],
            reader.array::<16>()?,
            reader.array::<24>()?,
            reader.array::<WRAPPED_DEK_LEN>()?,
            reader.u64()?,
            reader.array::<24>()?,
            reader.u32()?,
            reader.u32()?,
            reader.array::<6>()?,
        ))
    };
    let (
        magic,
        version,
        header_len,
        vault_id,
        kdf_id,
        [m_kib, t, p],
        kdf_salt,
        wrap_nonce,
        wrapped_dek,
        generation,
        payload_nonce,
        payload_ct_len,
        flags,
        reserved,
    ) = read().ok_or(VaultError::Malformed)?;
    if magic != VAULT_MAGIC {
        return Err(VaultError::Malformed);
    }
    if version != VAULT_VERSION {
        return Err(VaultError::UnsupportedVersion);
    }
    if usize::from(header_len) != VAULT_HEADER_LEN {
        return Err(VaultError::Malformed);
    }
    if vault_id == [0; 16] || generation == 0 {
        return Err(VaultError::Malformed);
    }
    if kdf_id != KDF_ID_ARGON2ID_V13 || (KdfParams { m_kib, t, p }) != *params {
        return Err(VaultError::UnsupportedParams);
    }
    let expected_len = usize::try_from(payload_ct_len)
        .ok()
        .and_then(|len| len.checked_add(VAULT_HEADER_LEN))
        .ok_or(VaultError::Malformed)?;
    if !(PAYLOAD_CT_MIN..=PAYLOAD_CT_MAX).contains(&payload_ct_len) || bytes.len() != expected_len {
        return Err(VaultError::Malformed);
    }
    if flags != 0 || reserved != [0; 6] {
        return Err(VaultError::Malformed);
    }
    Ok(Header {
        vault_id,
        kdf_salt,
        wrap_nonce,
        wrapped_dek,
        generation,
        payload_nonce,
        payload_ct_len,
    })
}

/// Structural check of `vault.ywv` bytes against `KDF_V3` (spec/02 §4.5 steps 1–7, no KDF).
/// Returns the generation, or the specific structural error.
///
/// # Errors
///
/// [`VaultError::Malformed`], [`VaultError::UnsupportedVersion`] or [`VaultError::UnsupportedParams`].
pub fn check_vault_header(bytes: &[u8]) -> Result<u64, VaultError> {
    decode_header(bytes, &KDF_V3).map(|header| header.generation)
}

/// The generation of a structurally valid file (vault: §4.5 steps 1–7; sidecars: §5.2), else `None`.
#[must_use]
pub fn peek_generation(kind: FileKind, bytes: &[u8]) -> Option<u64> {
    peek_generation_with(kind, bytes, &KDF_V3)
}

pub(crate) fn peek_generation_with(
    kind: FileKind,
    bytes: &[u8],
    params: &KdfParams,
) -> Option<u64> {
    match kind {
        FileKind::Vault => decode_header(bytes, params)
            .ok()
            .map(|header| header.generation),
        FileKind::Meta | FileKind::Journal => decode_sidecar_header(kind, bytes)
            .ok()
            .map(|header| header.generation),
    }
}

/// `KEK = HKDF-SHA256(salt, Argon2id(password, kdf_salt), info)` (spec/02 §4.3).
pub(crate) fn derive_kek(
    password: &VaultPassword,
    salt: &[u8; 16],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    #[cfg(test)]
    KDF_CALLS.with(|calls| calls.set(calls.get() + 1));
    let argon_params =
        Params::new(params.m_kib, params.t, params.p, Some(32)).map_err(|_| INTERNAL)?;
    let block_count = argon_params.block_count();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut blocks: Vec<Block> = Vec::new();
    blocks
        .try_reserve_exact(block_count)
        .map_err(|_| VaultError::OutOfMemory)?;
    blocks.resize(block_count, Block::default());
    let mut pw_kek = Zeroizing::new([0_u8; 32]);
    let result = argon.hash_password_into_with_memory(
        password.as_bytes(),
        salt,
        pw_kek.as_mut(),
        &mut blocks,
    );
    for block in &mut blocks {
        block.zeroize();
    }
    drop(blocks);
    result.map_err(|_| INTERNAL)?;
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_KEK_SALT), pw_kek.as_ref());
    let mut kek = Zeroizing::new([0_u8; 32]);
    hkdf.expand(HKDF_KEK_INFO, kek.as_mut())
        .map_err(|_| INTERNAL)?;
    Ok(kek)
}

fn seal_in_place(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<[u8; TAG_LEN], VaultError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(nonce), aad, buffer)
        .map_err(|_| INTERNAL)?;
    let mut out = [0_u8; TAG_LEN];
    out.copy_from_slice(tag.as_slice());
    Ok(out)
}

fn open_in_place(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> bool {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt_in_place_detached(XNonce::from_slice(nonce), aad, buffer, Tag::from_slice(tag))
        .is_ok()
}

/// One BIP39 record (`tag 1`).
pub(crate) struct Bip39Record {
    pub(crate) record_id: [u8; 16],
    pub(crate) created_unix: u64,
    pub(crate) mnemonic: Mnemonic,
    pub(crate) passphrase_used: bool,
    pub(crate) backup_confirmed: bool,
    pub(crate) passphrase_check: [u8; 4],
}

/// One imported EVM private key (`tag 2`).
pub(crate) struct RawKeyRecord {
    pub(crate) record_id: [u8; 16],
    pub(crate) created_unix: u64,
    pub(crate) key: Zeroizing<[u8; 32]>,
}

/// Decoded payload: exactly one BIP39 record followed by 0–15 raw keys.
pub(crate) struct Payload {
    pub(crate) bip39: Bip39Record,
    pub(crate) raw_keys: Vec<RawKeyRecord>,
}

fn valid_scalar(key: &[u8; 32]) -> bool {
    SecretKey::from_byte_array(*key).is_ok_and(|mut secret| {
        secret.non_secure_erase();
        true
    })
}

impl Payload {
    fn encoded_len(&self) -> Option<usize> {
        let bip39 = BIP39_RECORD_FIXED_LEN.checked_add(self.bip39.mnemonic.entropy().len())?;
        let raws = RAW_RECORD_LEN.checked_mul(self.raw_keys.len())?;
        PAYLOAD_HEADER_LEN.checked_add(bip39)?.checked_add(raws)
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if self.raw_keys.len() > MAX_RAW_KEYS {
            return Err(VaultError::RecordLimit);
        }
        let count = u16::try_from(self.raw_keys.len().saturating_add(1)).map_err(|_| INTERNAL)?;
        let len = self.encoded_len().ok_or(INTERNAL)?;
        let entropy = self.bip39.mnemonic.entropy();
        let mut out = Zeroizing::new(Vec::with_capacity(len));
        out.extend_from_slice(&PAYLOAD_MAGIC);
        out.extend_from_slice(&count.to_be_bytes());
        out.extend_from_slice(&[0_u8; 6]);
        out.push(TAG_BIP39);
        out.extend_from_slice(&self.bip39.record_id);
        out.extend_from_slice(&self.bip39.created_unix.to_be_bytes());
        out.push(u8::try_from(entropy.len()).map_err(|_| INTERNAL)?);
        out.extend_from_slice(entropy);
        out.push(u8::from(self.bip39.passphrase_used));
        out.push(u8::from(self.bip39.backup_confirmed));
        out.extend_from_slice(&self.bip39.passphrase_check);
        for raw in &self.raw_keys {
            out.push(TAG_RAW_KEY);
            out.extend_from_slice(&raw.record_id);
            out.extend_from_slice(&raw.created_unix.to_be_bytes());
            out.extend_from_slice(raw.key.as_slice());
        }
        if out.len() != len || out.capacity() != len {
            return Err(INTERNAL);
        }
        Ok(out)
    }

    /// Decodes and validates every rule of spec/02 §4.6; any violation is `PayloadCorrupt`.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, VaultError> {
        Self::decode_inner(bytes).ok_or(VaultError::PayloadCorrupt)
    }

    fn decode_inner(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(bytes);
        if reader.array::<8>()? != PAYLOAD_MAGIC {
            return None;
        }
        let count = usize::from(reader.u16()?);
        if !(1..=MAX_RECORDS).contains(&count) || reader.array::<6>()? != [0; 6] {
            return None;
        }
        let mut ids: Vec<[u8; 16]> = Vec::with_capacity(count);
        let mut take_id = |reader: &mut Reader<'_>| -> Option<[u8; 16]> {
            let id = reader.array::<16>()?;
            if id == [0; 16] || ids.contains(&id) {
                return None;
            }
            ids.push(id);
            Some(id)
        };
        if reader.u8()? != TAG_BIP39 {
            return None;
        }
        let record_id = take_id(&mut reader)?;
        let created_unix = reader.u64()?;
        let entropy_len = usize::from(reader.u8()?);
        let mnemonic = Mnemonic::from_entropy(reader.slice(entropy_len)?).ok()?;
        let flags = reader.u8()?;
        let backup_state = reader.u8()?;
        let passphrase_check = reader.array::<4>()?;
        let passphrase_used = match flags {
            0 => false,
            1 => true,
            _ => return None,
        };
        let backup_confirmed = match backup_state {
            0 => false,
            1 => true,
            _ => return None,
        };
        if (!passphrase_used && passphrase_check != [0; 4])
            || (!backup_confirmed && passphrase_used)
        {
            return None;
        }
        let bip39 = Bip39Record {
            record_id,
            created_unix,
            mnemonic,
            passphrase_used,
            backup_confirmed,
            passphrase_check,
        };
        let mut raw_keys: Vec<RawKeyRecord> = Vec::with_capacity(count.saturating_sub(1));
        for _ in 1..count {
            if reader.u8()? != TAG_RAW_KEY {
                return None;
            }
            let record_id = take_id(&mut reader)?;
            let created_unix = reader.u64()?;
            let key = Zeroizing::new(reader.array::<32>()?);
            let duplicate = raw_keys.iter().fold(0_u8, |seen, other| {
                seen | other.key.as_slice().ct_eq(key.as_slice()).unwrap_u8()
            });
            if !valid_scalar(&key) || duplicate != 0 {
                return None;
            }
            raw_keys.push(RawKeyRecord {
                record_id,
                created_unix,
                key,
            });
        }
        reader.is_empty().then_some(Self { bip39, raw_keys })
    }
}

fn payload_ct_len(plaintext: &[u8]) -> Result<u32, VaultError> {
    let len = plaintext
        .len()
        .checked_add(TAG_LEN)
        .and_then(|len| u32::try_from(len).ok())
        .ok_or(INTERNAL)?;
    if !(PAYLOAD_CT_MIN..=PAYLOAD_CT_MAX).contains(&len) {
        return Err(INTERNAL);
    }
    Ok(len)
}

/// `header ‖ XChaCha20-Poly1305(DEK, payload_nonce, plaintext, aad = header)`.
fn seal_payload(
    head: &[u8; VAULT_HEADER_LEN],
    dek: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let total = VAULT_HEADER_LEN
        .checked_add(plaintext.len())
        .and_then(|len| len.checked_add(TAG_LEN))
        .ok_or(INTERNAL)?;
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.extend_from_slice(head);
    out.extend_from_slice(plaintext);
    let (_, body) = out.split_at_mut(VAULT_HEADER_LEN);
    let tag = seal_in_place(dek, nonce, head, body)?;
    out.extend_from_slice(&tag);
    if out.len() != total || out.capacity() != total {
        return Err(INTERNAL);
    }
    Ok(core::mem::take(&mut *out))
}

fn open_payload_plain(bytes: &[u8], header: &Header, dek: &[u8; 32]) -> Option<Zeroizing<Vec<u8>>> {
    let (head, rest) = bytes.split_first_chunk::<VAULT_HEADER_LEN>()?;
    let (ciphertext, tag) = rest.split_last_chunk::<TAG_LEN>()?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(ciphertext.len()));
    plaintext.extend_from_slice(ciphertext);
    open_in_place(dek, &header.payload_nonce, head, &mut plaintext, tag).then_some(plaintext)
}

fn unwrap_with_kek(
    header: &Header,
    kek: &[u8; 32],
    params: &KdfParams,
) -> Option<Zeroizing<[u8; 32]>> {
    let aad = key_block(
        &header.vault_id,
        params,
        &header.kdf_salt,
        &header.wrap_nonce,
    );
    let (ciphertext, tag) = header.wrapped_dek.split_first_chunk::<32>()?;
    let tag = tag.first_chunk::<TAG_LEN>()?;
    let mut dek = Zeroizing::new(*ciphertext);
    open_in_place(kek, &header.wrap_nonce, &aad, dek.as_mut(), tag).then_some(dek)
}

/// Steps 1–8: structure, Argon2 → KEK, DEK unwrap. Wrong password and a tampered key section
/// are both `UnlockFailed`.
pub(crate) fn unwrap_dek(
    bytes: &[u8],
    password: &VaultPassword,
    params: &KdfParams,
) -> Result<(Header, Zeroizing<[u8; 32]>), VaultError> {
    let header = decode_header(bytes, params)?;
    let kek = derive_kek(password, &header.kdf_salt, params)?;
    let dek = unwrap_with_kek(&header, &kek, params).ok_or(VaultError::UnlockFailed)?;
    Ok((header, dek))
}

/// Step 9: payload authentication and decoding with the DEK.
pub(crate) fn decrypt_payload(
    bytes: &[u8],
    dek: &[u8; 32],
    params: &KdfParams,
) -> Result<Payload, VaultError> {
    let header = decode_header(bytes, params)?;
    let plaintext = open_payload_plain(bytes, &header, dek).ok_or(VaultError::PayloadCorrupt)?;
    Payload::decode(&plaintext)
}

/// Inputs of a write that derives a new KEK (`Create`, `Rewrap`).
pub(crate) struct SealMaterial<'a> {
    pub(crate) password: &'a VaultPassword,
    pub(crate) vault_id: [u8; 16],
    pub(crate) dek: &'a [u8; 32],
    pub(crate) kdf_salt: [u8; 16],
    pub(crate) wrap_nonce: [u8; 24],
    pub(crate) payload_nonce: [u8; 24],
    pub(crate) generation: u64,
    pub(crate) payload: &'a Payload,
}

/// `Create`/`Rewrap`: Argon2 once, wrap the DEK, encrypt the payload, then self-check the bytes
/// (decode, unwrap with the KEK in hand, decrypt and compare) before returning them.
pub(crate) fn seal_create_with(
    material: &SealMaterial<'_>,
    params: &KdfParams,
) -> Result<Vec<u8>, VaultError> {
    if material.vault_id == [0; 16] || material.generation == 0 {
        return Err(INTERNAL);
    }
    let plaintext = material.payload.encode()?;
    let payload_ct_len = payload_ct_len(&plaintext)?;
    let kek = derive_kek(material.password, &material.kdf_salt, params)?;
    let aad = key_block(
        &material.vault_id,
        params,
        &material.kdf_salt,
        &material.wrap_nonce,
    );
    let mut wrapped = Zeroizing::new(*material.dek);
    let tag = seal_in_place(&kek, &material.wrap_nonce, &aad, wrapped.as_mut())?;
    let mut wrapped_dek = [0_u8; WRAPPED_DEK_LEN];
    let (dek_part, tag_part) = wrapped_dek.split_at_mut(32);
    dek_part.copy_from_slice(wrapped.as_slice());
    tag_part.copy_from_slice(&tag);
    let header = Header {
        vault_id: material.vault_id,
        kdf_salt: material.kdf_salt,
        wrap_nonce: material.wrap_nonce,
        wrapped_dek,
        generation: material.generation,
        payload_nonce: material.payload_nonce,
        payload_ct_len,
    };
    let head = encode_header(&header, params)?;
    let mut out = seal_payload(&head, material.dek, &material.payload_nonce, &plaintext)?;
    inject_corruption(&mut out);
    let decoded = decode_header(&out, params).map_err(|_| INTERNAL)?;
    let unwrapped = unwrap_with_kek(&decoded, &kek, params).ok_or(INTERNAL)?;
    let reopened = open_payload_plain(&out, &decoded, material.dek).ok_or(INTERNAL)?;
    let same_dek = unwrapped.as_slice().ct_eq(material.dek.as_slice());
    let same_payload = reopened.as_slice().ct_eq(plaintext.as_slice());
    if (same_dek & same_payload).unwrap_u8() != 1 {
        return Err(INTERNAL);
    }
    Ok(out)
}

/// `PayloadRewrite`: keep `header[0..130]`, `generation + 1`, new payload nonce, no KDF.
pub(crate) fn seal_payload_rewrite(
    current: &[u8],
    dek: &[u8; 32],
    payload: &Payload,
    payload_nonce: [u8; 24],
    params: &KdfParams,
) -> Result<Vec<u8>, VaultError> {
    let old = decode_header(current, params)?;
    let generation = old.generation.checked_add(1).ok_or(INTERNAL)?;
    let plaintext = payload.encode()?;
    let header = Header {
        generation,
        payload_nonce,
        payload_ct_len: payload_ct_len(&plaintext)?,
        ..old
    };
    let head = encode_header(&header, params)?;
    let mut out = seal_payload(&head, dek, &payload_nonce, &plaintext)?;
    inject_corruption(&mut out);
    let decoded = decode_header(&out, params).map_err(|_| INTERNAL)?;
    let reopened = open_payload_plain(&out, &decoded, dek).ok_or(INTERNAL)?;
    let key_section_kept = out.get(..KEY_SECTION_END) == current.get(..KEY_SECTION_END);
    if !key_section_kept || reopened.as_slice().ct_eq(plaintext.as_slice()).unwrap_u8() != 1 {
        return Err(INTERNAL);
    }
    Ok(out)
}

/// Parsed sidecar header (spec/02 §5.2).
pub(crate) struct SidecarHeader {
    pub(crate) vault_id: [u8; 16],
    pub(crate) generation: u64,
    nonce: [u8; 24],
}

fn sidecar_magic(kind: FileKind) -> Result<([u8; 8], usize), VaultError> {
    match kind {
        FileKind::Meta => Ok((META_MAGIC, META_MAX_PLAINTEXT)),
        FileKind::Journal => Ok((JOURNAL_MAGIC, JOURNAL_MAX_PLAINTEXT)),
        FileKind::Vault => Err(VaultError::InvalidState),
    }
}

pub(crate) fn decode_sidecar_header(
    kind: FileKind,
    bytes: &[u8],
) -> Result<SidecarHeader, VaultError> {
    let (magic, max_plaintext) = sidecar_magic(kind)?;
    let corrupt = VaultError::SidecarCorrupt(kind);
    let head = bytes.first_chunk::<SIDECAR_HEADER_LEN>().ok_or(corrupt)?;
    let mut reader = Reader::new(head);
    let mut read = || -> Option<_> {
        Some((
            reader.array::<8>()?,
            reader.u16()?,
            reader.u16()?,
            reader.array::<16>()?,
            reader.u64()?,
            reader.array::<24>()?,
            reader.u32()?,
        ))
    };
    let (file_magic, version, header_len, vault_id, generation, nonce, ct_len) =
        read().ok_or(corrupt)?;
    let ct_len = usize::try_from(ct_len).map_err(|_| corrupt)?;
    let max_ct = max_plaintext.saturating_add(TAG_LEN);
    let valid = file_magic == magic
        && version == SIDECAR_VERSION
        && usize::from(header_len) == SIDECAR_HEADER_LEN
        && generation >= 1
        && (TAG_LEN..=max_ct).contains(&ct_len)
        && SIDECAR_HEADER_LEN.checked_add(ct_len) == Some(bytes.len());
    if !valid {
        return Err(corrupt);
    }
    Ok(SidecarHeader {
        vault_id,
        generation,
        nonce,
    })
}

/// `HKDF-SHA256(salt = none, ikm = DEK, info = "your-wallet/v3/{meta|journal}")`.
fn sidecar_key(dek: &[u8; 32], kind: FileKind) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let info = match kind {
        FileKind::Meta => HKDF_META_INFO,
        FileKind::Journal => HKDF_JOURNAL_INFO,
        FileKind::Vault => return Err(VaultError::InvalidState),
    };
    let mut key = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(None, dek)
        .expand(info, key.as_mut())
        .map_err(|_| INTERNAL)?;
    Ok(key)
}

fn open_sidecar_body(
    bytes: &[u8],
    header: &SidecarHeader,
    key: &[u8; 32],
) -> Option<Zeroizing<Vec<u8>>> {
    let (head, rest) = bytes.split_first_chunk::<SIDECAR_HEADER_LEN>()?;
    let (ciphertext, tag) = rest.split_last_chunk::<TAG_LEN>()?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(ciphertext.len()));
    plaintext.extend_from_slice(ciphertext);
    open_in_place(key, &header.nonce, head, &mut plaintext, tag).then_some(plaintext)
}

/// Seals a sidecar file and self-checks it.
pub(crate) fn seal_sidecar(
    kind: FileKind,
    vault_id: &[u8; 16],
    generation: u64,
    nonce: &[u8; 24],
    dek: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let (magic, max_plaintext) = sidecar_magic(kind)?;
    if plaintext.len() > max_plaintext {
        return Err(VaultError::Storage(StorageError::TooLarge));
    }
    let ct_len = u32::try_from(plaintext.len().saturating_add(TAG_LEN)).map_err(|_| INTERNAL)?;
    let key = sidecar_key(dek, kind)?;
    let total = SIDECAR_HEADER_LEN
        .checked_add(plaintext.len())
        .and_then(|len| len.checked_add(TAG_LEN))
        .ok_or(INTERNAL)?;
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.extend_from_slice(&magic);
    out.extend_from_slice(&SIDECAR_VERSION.to_be_bytes());
    out.extend_from_slice(
        &u16::try_from(SIDECAR_HEADER_LEN)
            .map_err(|_| INTERNAL)?
            .to_be_bytes(),
    );
    out.extend_from_slice(vault_id);
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct_len.to_be_bytes());
    let head = *out.first_chunk::<SIDECAR_HEADER_LEN>().ok_or(INTERNAL)?;
    out.extend_from_slice(plaintext);
    let (_, body) = out.split_at_mut(SIDECAR_HEADER_LEN);
    let tag = seal_in_place(&key, nonce, &head, body)?;
    out.extend_from_slice(&tag);
    if out.len() != total || out.capacity() != total {
        return Err(INTERNAL);
    }
    let out = core::mem::take(&mut *out);
    let header = decode_sidecar_header(kind, &out).map_err(|_| INTERNAL)?;
    let reopened = open_sidecar_body(&out, &header, &key).ok_or(INTERNAL)?;
    if header.generation != generation || reopened.as_slice().ct_eq(plaintext).unwrap_u8() != 1 {
        return Err(INTERNAL);
    }
    Ok(out)
}

/// Opens a sidecar: structure → `SidecarCorrupt`, other vault → `SidecarVaultMismatch`,
/// authentication → `SidecarCorrupt`.
pub(crate) fn open_sidecar(
    kind: FileKind,
    bytes: &[u8],
    vault_id: &[u8; 16],
    dek: &[u8; 32],
) -> Result<(u64, Zeroizing<Vec<u8>>), VaultError> {
    let header = decode_sidecar_header(kind, bytes)?;
    if header.vault_id != *vault_id {
        return Err(VaultError::SidecarVaultMismatch(kind));
    }
    let key = sidecar_key(dek, kind)?;
    let plaintext =
        open_sidecar_body(bytes, &header, &key).ok_or(VaultError::SidecarCorrupt(kind))?;
    Ok((header.generation, plaintext))
}
