//! Vault-bound authenticated custom-token metadata for the Sepolia demo.
//!
//! The file is fixed-size, accepts at most 32 contracts, and is encrypted with
//! a key derived independently by the v2 vault. It contains public metadata,
//! but authentication prevents accidental cross-vault or cross-network reuse.

#![cfg_attr(not(test), allow(dead_code))]

use core::fmt;

use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

const FILE_MAGIC: &[u8; 8] = b"YWSTK001";
const PAYLOAD_MAGIC: &[u8; 8] = b"YWSTP001";
const VERSION: u16 = 1;
const AEAD_XCHACHA20_POLY1305: u16 = 1;
const PAYLOAD_SCHEMA: u16 = 1;
const SEPOLIA_CHAIN_ID: u64 = 11_155_111;
const HEADER_BYTES: usize = 80;
const PAYLOAD_PREFIX_BYTES: usize = 48;
const RECORD_BYTES: usize = 80;
const TOKEN_CAPACITY: usize = 32;
const TOKEN_CAPACITY_U16: u16 = 32;
const PAYLOAD_BYTES: usize = PAYLOAD_PREFIX_BYTES + RECORD_BYTES * TOKEN_CAPACITY;
const AEAD_TAG_BYTES: usize = 16;
const CIPHERTEXT_BYTES: usize = PAYLOAD_BYTES + AEAD_TAG_BYTES;
const FILE_BYTES: usize = HEADER_BYTES + CIPHERTEXT_BYTES;
const MAX_SYMBOL_BYTES: usize = 16;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum TokenStoreError {
    InvalidInput,
    Full,
    Duplicate,
    NotFound,
    RandomnessUnavailable,
    AuthenticationFailed,
    InvalidRecord,
    GenerationOverflow,
}

impl fmt::Debug for TokenStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "TokenStoreError::InvalidInput",
            Self::Full => "TokenStoreError::Full",
            Self::Duplicate => "TokenStoreError::Duplicate",
            Self::NotFound => "TokenStoreError::NotFound",
            Self::RandomnessUnavailable => "TokenStoreError::RandomnessUnavailable",
            Self::AuthenticationFailed => "TokenStoreError::AuthenticationFailed",
            Self::InvalidRecord => "TokenStoreError::InvalidRecord",
            Self::GenerationOverflow => "TokenStoreError::GenerationOverflow",
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct TokenEntry {
    contract: [u8; 20],
    decimals: u8,
    symbol: Option<String>,
    code_hash: [u8; 32],
}

impl TokenEntry {
    pub(crate) fn new(
        contract: [u8; 20],
        decimals: u8,
        symbol: Option<String>,
        code_hash: [u8; 32],
    ) -> Result<Self, TokenStoreError> {
        if contract == [0; 20] || decimals > 36 {
            return Err(TokenStoreError::InvalidInput);
        }
        if let Some(symbol) = symbol.as_deref() {
            validate_symbol(symbol)?;
        }
        Ok(Self {
            contract,
            decimals,
            symbol,
            code_hash,
        })
    }

    pub(crate) const fn contract(&self) -> &[u8; 20] {
        &self.contract
    }

    pub(crate) const fn decimals(&self) -> u8 {
        self.decimals
    }

    pub(crate) fn symbol(&self) -> Option<&str> {
        self.symbol.as_deref()
    }

    pub(crate) const fn code_hash(&self) -> &[u8; 32] {
        &self.code_hash
    }
}

impl fmt::Debug for TokenEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenEntry([REDACTED])")
    }
}

pub(crate) struct TokenStore {
    vault_id: [u8; 16],
    generation: u64,
    entries: Vec<TokenEntry>,
}

impl TokenStore {
    pub(crate) fn empty(vault_id: [u8; 16]) -> Result<Self, TokenStoreError> {
        if vault_id == [0; 16] {
            return Err(TokenStoreError::InvalidInput);
        }
        Ok(Self {
            vault_id,
            generation: 0,
            entries: Vec::with_capacity(TOKEN_CAPACITY),
        })
    }

    pub(crate) const fn vault_id(&self) -> &[u8; 16] {
        &self.vault_id
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn entries(&self) -> &[TokenEntry] {
        &self.entries
    }

    pub(crate) fn add(&mut self, entry: TokenEntry) -> Result<(), TokenStoreError> {
        if self.entries.len() >= TOKEN_CAPACITY {
            return Err(TokenStoreError::Full);
        }
        if self
            .entries
            .iter()
            .any(|existing| existing.contract == entry.contract)
        {
            return Err(TokenStoreError::Duplicate);
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(TokenStoreError::GenerationOverflow)?;
        self.entries.push(entry);
        self.generation = next_generation;
        Ok(())
    }

    pub(crate) fn remove(&mut self, contract: [u8; 20]) -> Result<(), TokenStoreError> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.contract == contract)
            .ok_or(TokenStoreError::NotFound)?;
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(TokenStoreError::GenerationOverflow)?;
        self.entries.remove(index);
        self.generation = next_generation;
        Ok(())
    }

    pub(crate) fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, TokenStoreError> {
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| TokenStoreError::RandomnessUnavailable)?;
        self.seal_with_nonce(key, nonce)
    }

    fn seal_with_nonce(&self, key: &[u8; 32], nonce: [u8; 24]) -> Result<Vec<u8>, TokenStoreError> {
        if self.vault_id == [0; 16] || self.generation == 0 || nonce == [0; 24] {
            return Err(TokenStoreError::InvalidInput);
        }
        validate_entries(&self.entries)?;

        let header = encode_header(self.vault_id, self.generation, nonce);
        let plaintext = Zeroizing::new(encode_payload(
            self.vault_id,
            self.generation,
            &self.entries,
        )?);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &header,
                },
            )
            .map_err(|_| TokenStoreError::AuthenticationFailed)?;
        if ciphertext.len() != CIPHERTEXT_BYTES {
            return Err(TokenStoreError::AuthenticationFailed);
        }
        let mut file = Vec::with_capacity(FILE_BYTES);
        file.extend_from_slice(&header);
        file.extend_from_slice(&ciphertext);
        if file.len() != FILE_BYTES {
            return Err(TokenStoreError::InvalidRecord);
        }
        Ok(file)
    }

    pub(crate) fn open(
        bytes: &[u8],
        key: &[u8; 32],
        expected_vault_id: &[u8; 16],
    ) -> Result<Self, TokenStoreError> {
        if bytes.len() != FILE_BYTES || expected_vault_id == &[0; 16] {
            return Err(TokenStoreError::InvalidRecord);
        }
        let header: &[u8; HEADER_BYTES] = bytes[..HEADER_BYTES]
            .try_into()
            .map_err(|_| TokenStoreError::InvalidRecord)?;
        let decoded = decode_header(header, expected_vault_id)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&decoded.nonce),
                Payload {
                    msg: &bytes[HEADER_BYTES..],
                    aad: header,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| TokenStoreError::AuthenticationFailed)?;
        if plaintext.len() != PAYLOAD_BYTES {
            return Err(TokenStoreError::InvalidRecord);
        }
        let entries = decode_payload(plaintext.as_slice(), expected_vault_id, decoded.generation)?;
        Ok(Self {
            vault_id: *expected_vault_id,
            generation: decoded.generation,
            entries,
        })
    }
}

impl fmt::Debug for TokenStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenStore([REDACTED])")
    }
}

struct DecodedHeader {
    generation: u64,
    nonce: [u8; 24],
}

fn encode_header(vault_id: [u8; 16], generation: u64, nonce: [u8; 24]) -> [u8; HEADER_BYTES] {
    let mut header = [0_u8; HEADER_BYTES];
    header[..8].copy_from_slice(FILE_MAGIC);
    header[8..10].copy_from_slice(&VERSION.to_be_bytes());
    header[10..12].copy_from_slice(&(HEADER_BYTES as u16).to_be_bytes());
    header[12..14].copy_from_slice(&AEAD_XCHACHA20_POLY1305.to_be_bytes());
    header[14..16].copy_from_slice(&PAYLOAD_SCHEMA.to_be_bytes());
    header[16..24].copy_from_slice(&SEPOLIA_CHAIN_ID.to_be_bytes());
    header[24..32].copy_from_slice(&generation.to_be_bytes());
    header[32..48].copy_from_slice(&vault_id);
    header[48..72].copy_from_slice(&nonce);
    header[72..76].copy_from_slice(&(CIPHERTEXT_BYTES as u32).to_be_bytes());
    header[76..78].copy_from_slice(&TOKEN_CAPACITY_U16.to_be_bytes());
    header
}

fn decode_header(
    header: &[u8; HEADER_BYTES],
    expected_vault_id: &[u8; 16],
) -> Result<DecodedHeader, TokenStoreError> {
    if &header[..8] != FILE_MAGIC
        || read_u16(&header[8..10])? != VERSION
        || usize::from(read_u16(&header[10..12])?) != HEADER_BYTES
        || read_u16(&header[12..14])? != AEAD_XCHACHA20_POLY1305
        || read_u16(&header[14..16])? != PAYLOAD_SCHEMA
        || read_u64(&header[16..24])? != SEPOLIA_CHAIN_ID
        || &header[32..48] != expected_vault_id
        || usize::try_from(read_u32(&header[72..76])?).ok() != Some(CIPHERTEXT_BYTES)
        || read_u16(&header[76..78])? != TOKEN_CAPACITY_U16
        || header[78..].iter().any(|byte| *byte != 0)
    {
        return Err(TokenStoreError::InvalidRecord);
    }
    let generation = read_u64(&header[24..32])?;
    let nonce: [u8; 24] = header[48..72]
        .try_into()
        .map_err(|_| TokenStoreError::InvalidRecord)?;
    if generation == 0 || nonce == [0; 24] {
        return Err(TokenStoreError::InvalidRecord);
    }
    Ok(DecodedHeader { generation, nonce })
}

fn encode_payload(
    vault_id: [u8; 16],
    generation: u64,
    entries: &[TokenEntry],
) -> Result<Vec<u8>, TokenStoreError> {
    let count = u16::try_from(entries.len()).map_err(|_| TokenStoreError::Full)?;
    let mut payload = vec![0_u8; PAYLOAD_BYTES];
    payload[..8].copy_from_slice(PAYLOAD_MAGIC);
    payload[8..10].copy_from_slice(&PAYLOAD_SCHEMA.to_be_bytes());
    payload[10..12].copy_from_slice(&count.to_be_bytes());
    payload[12..14].copy_from_slice(&TOKEN_CAPACITY_U16.to_be_bytes());
    payload[16..24].copy_from_slice(&generation.to_be_bytes());
    payload[24..40].copy_from_slice(&vault_id);
    payload[40..48].copy_from_slice(&SEPOLIA_CHAIN_ID.to_be_bytes());
    for (index, entry) in entries.iter().enumerate() {
        encode_entry(entry, &mut payload[record_range(index)])?;
    }
    Ok(payload)
}

fn decode_payload(
    payload: &[u8],
    expected_vault_id: &[u8; 16],
    expected_generation: u64,
) -> Result<Vec<TokenEntry>, TokenStoreError> {
    if payload.len() != PAYLOAD_BYTES
        || &payload[..8] != PAYLOAD_MAGIC
        || read_u16(&payload[8..10])? != PAYLOAD_SCHEMA
        || read_u16(&payload[12..14])? != TOKEN_CAPACITY_U16
        || payload[14..16].iter().any(|byte| *byte != 0)
        || read_u64(&payload[16..24])? != expected_generation
        || &payload[24..40] != expected_vault_id
        || read_u64(&payload[40..48])? != SEPOLIA_CHAIN_ID
    {
        return Err(TokenStoreError::InvalidRecord);
    }
    let count = usize::from(read_u16(&payload[10..12])?);
    if count > TOKEN_CAPACITY {
        return Err(TokenStoreError::InvalidRecord);
    }
    let mut entries = Vec::with_capacity(TOKEN_CAPACITY);
    for index in 0..count {
        entries.push(decode_entry(&payload[record_range(index)])?);
    }
    for index in count..TOKEN_CAPACITY {
        if payload[record_range(index)].iter().any(|byte| *byte != 0) {
            return Err(TokenStoreError::InvalidRecord);
        }
    }
    validate_entries(&entries)?;
    Ok(entries)
}

fn encode_entry(entry: &TokenEntry, output: &mut [u8]) -> Result<(), TokenStoreError> {
    if output.len() != RECORD_BYTES {
        return Err(TokenStoreError::InvalidRecord);
    }
    output.fill(0);
    output[..20].copy_from_slice(&entry.contract);
    output[20] = entry.decimals;
    let symbol = entry.symbol.as_deref().unwrap_or("").as_bytes();
    output[21] = u8::try_from(symbol.len()).map_err(|_| TokenStoreError::InvalidInput)?;
    output[22..24].copy_from_slice(&1_u16.to_be_bytes());
    output[24..56].copy_from_slice(&entry.code_hash);
    output[56..56 + symbol.len()].copy_from_slice(symbol);
    Ok(())
}

fn decode_entry(input: &[u8]) -> Result<TokenEntry, TokenStoreError> {
    if input.len() != RECORD_BYTES
        || read_u16(&input[22..24])? != 1
        || input[72..].iter().any(|byte| *byte != 0)
    {
        return Err(TokenStoreError::InvalidRecord);
    }
    let symbol_length = usize::from(input[21]);
    if symbol_length > MAX_SYMBOL_BYTES
        || input[56 + symbol_length..72].iter().any(|byte| *byte != 0)
    {
        return Err(TokenStoreError::InvalidRecord);
    }
    let contract: [u8; 20] = input[..20]
        .try_into()
        .map_err(|_| TokenStoreError::InvalidRecord)?;
    let code_hash: [u8; 32] = input[24..56]
        .try_into()
        .map_err(|_| TokenStoreError::InvalidRecord)?;
    let symbol = if symbol_length == 0 {
        None
    } else {
        Some(
            core::str::from_utf8(&input[56..56 + symbol_length])
                .map_err(|_| TokenStoreError::InvalidRecord)?
                .to_owned(),
        )
    };
    TokenEntry::new(contract, input[20], symbol, code_hash)
        .map_err(|_| TokenStoreError::InvalidRecord)
}

fn validate_entries(entries: &[TokenEntry]) -> Result<(), TokenStoreError> {
    if entries.len() > TOKEN_CAPACITY {
        return Err(TokenStoreError::Full);
    }
    for (index, entry) in entries.iter().enumerate() {
        if entry.contract == [0; 20] || entry.decimals > 36 {
            return Err(TokenStoreError::InvalidRecord);
        }
        if let Some(symbol) = entry.symbol.as_deref() {
            validate_symbol(symbol).map_err(|_| TokenStoreError::InvalidRecord)?;
        }
        if entries[index + 1..]
            .iter()
            .any(|other| other.contract == entry.contract)
        {
            return Err(TokenStoreError::Duplicate);
        }
    }
    Ok(())
}

fn validate_symbol(symbol: &str) -> Result<(), TokenStoreError> {
    if symbol.is_empty()
        || symbol.len() > MAX_SYMBOL_BYTES
        || !symbol.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'$' | b'+' | b'-' | b'.' | b'_')
        })
    {
        return Err(TokenStoreError::InvalidInput);
    }
    Ok(())
}

fn record_range(index: usize) -> core::ops::Range<usize> {
    let start = PAYLOAD_PREFIX_BYTES + index * RECORD_BYTES;
    start..start + RECORD_BYTES
}

fn read_u16(bytes: &[u8]) -> Result<u16, TokenStoreError> {
    bytes
        .try_into()
        .map(u16::from_be_bytes)
        .map_err(|_| TokenStoreError::InvalidRecord)
}

fn read_u32(bytes: &[u8]) -> Result<u32, TokenStoreError> {
    bytes
        .try_into()
        .map(u32::from_be_bytes)
        .map_err(|_| TokenStoreError::InvalidRecord)
}

fn read_u64(bytes: &[u8]) -> Result<u64, TokenStoreError> {
    bytes
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| TokenStoreError::InvalidRecord)
}

#[cfg(test)]
mod tests {
    use super::{
        FILE_BYTES, HEADER_BYTES, PAYLOAD_BYTES, RECORD_BYTES, TOKEN_CAPACITY, TokenEntry,
        TokenStore, TokenStoreError, record_range,
    };

    fn entry(marker: u8) -> TokenEntry {
        let mut address = [marker; 20];
        address[0] = 0x11;
        TokenEntry::new(address, 18, Some(format!("TOK{marker}")), [marker; 32])
            .expect("valid token entry")
    }

    #[test]
    fn fixed_file_round_trip_binds_vault_key_and_metadata() {
        let vault_id = [0x11; 16];
        let key = [0x22; 32];
        let mut store = TokenStore::empty(vault_id).expect("empty store");
        store.add(entry(1)).expect("add one");
        store
            .add(TokenEntry::new([0x33; 20], 6, None, [0x44; 32]).expect("second entry"))
            .expect("add two");
        let bytes = store
            .seal_with_nonce(&key, [0x55; 24])
            .expect("seal token store");
        assert_eq!(bytes.len(), FILE_BYTES);

        let opened = TokenStore::open(&bytes, &key, &vault_id).expect("open token store");
        assert_eq!(opened.vault_id(), &vault_id);
        assert_eq!(opened.generation(), 2);
        assert_eq!(opened.entries().len(), 2);
        assert_eq!(opened.entries()[0].symbol(), Some("TOK1"));
        assert_eq!(opened.entries()[1].symbol(), None);
        assert_eq!(opened.entries()[1].decimals(), 6);
        assert_eq!(opened.entries()[1].code_hash(), &[0x44; 32]);
        assert_eq!(format!("{opened:?}"), "TokenStore([REDACTED])");
    }

    #[test]
    fn production_random_nonce_seal_round_trips() {
        let vault_id = [0x11; 16];
        let key = [0x22; 32];
        let mut store = TokenStore::empty(vault_id).expect("empty store");
        store.add(entry(1)).expect("add");
        let first = store.seal(&key).expect("seal with OS randomness");
        let second = store.seal(&key).expect("reseal with OS randomness");
        assert_ne!(first, second);
        assert_eq!(
            TokenStore::open(&first, &key, &vault_id)
                .expect("open randomized store")
                .entries(),
            store.entries()
        );
    }

    #[test]
    fn header_and_ciphertext_mutations_wrong_key_and_wrong_vault_fail() {
        let vault_id = [0x11; 16];
        let key = [0x22; 32];
        let mut store = TokenStore::empty(vault_id).expect("empty store");
        store.add(entry(1)).expect("add");
        let bytes = store
            .seal_with_nonce(&key, [0x55; 24])
            .expect("seal token store");

        assert!(TokenStore::open(&bytes, &[0x23; 32], &vault_id).is_err());
        assert!(TokenStore::open(&bytes, &key, &[0x12; 16]).is_err());
        for index in 0..bytes.len() {
            let mut mutated = bytes.clone();
            mutated[index] ^= 1;
            assert!(TokenStore::open(&mutated, &key, &vault_id).is_err());
        }
        for length in 0..bytes.len() {
            assert!(TokenStore::open(&bytes[..length], &key, &vault_id).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(TokenStore::open(&trailing, &key, &vault_id).is_err());
    }

    #[test]
    fn duplicate_capacity_remove_and_generation_are_exact() {
        let mut store = TokenStore::empty([0x11; 16]).expect("empty store");
        assert_eq!(store.generation(), 0);
        store.add(entry(1)).expect("first add");
        assert_eq!(store.add(entry(1)), Err(TokenStoreError::Duplicate));
        assert_eq!(store.generation(), 1);
        for marker in 2..=TOKEN_CAPACITY as u8 {
            store.add(entry(marker)).expect("fill capacity");
        }
        assert_eq!(store.entries().len(), TOKEN_CAPACITY);
        assert_eq!(store.add(entry(99)), Err(TokenStoreError::Full));
        assert_eq!(store.remove([0x77; 20]), Err(TokenStoreError::NotFound));
        let first = *store.entries()[0].contract();
        store.remove(first).expect("remove existing");
        assert_eq!(store.entries().len(), TOKEN_CAPACITY - 1);
        assert_eq!(store.generation(), TOKEN_CAPACITY as u64 + 1);
    }

    #[test]
    fn entries_reject_unsafe_or_ambiguous_metadata() {
        for (address, decimals, symbol) in [
            ([0; 20], 18, Some("TOK".to_owned())),
            ([1; 20], 37, Some("TOK".to_owned())),
            ([1; 20], 18, Some(String::new())),
            ([1; 20], 18, Some("has space".to_owned())),
            ([1; 20], 18, Some("0123456789abcdefg".to_owned())),
        ] {
            assert_eq!(
                TokenEntry::new(address, decimals, symbol, [2; 32]),
                Err(TokenStoreError::InvalidInput)
            );
        }
        assert_eq!(format!("{:?}", entry(1)), "TokenEntry([REDACTED])");
    }

    #[test]
    fn fixed_layout_sizes_and_unused_slots_are_zero() {
        assert_eq!(PAYLOAD_BYTES, 2_608);
        assert_eq!(FILE_BYTES, 2_704);
        assert_eq!(HEADER_BYTES, 80);
        assert_eq!(RECORD_BYTES, 80);

        let vault_id = [0x11; 16];
        let key = [0x22; 32];
        let mut store = TokenStore::empty(vault_id).expect("empty store");
        store.add(entry(1)).expect("add");
        let bytes = store
            .seal_with_nonce(&key, [0x55; 24])
            .expect("seal token store");
        let opened = TokenStore::open(&bytes, &key, &vault_id).expect("open");
        assert_eq!(opened.entries().len(), 1);

        // The strict payload decoder's unused-slot rule is also exercised by
        // constructing and mutating the exact unencrypted canonical payload.
        let mut payload = super::encode_payload(vault_id, 1, &[entry(1)]).expect("payload");
        payload[record_range(1).start] = 1;
        assert!(super::decode_payload(&payload, &vault_id, 1).is_err());
    }

    #[test]
    fn empty_or_zero_nonce_store_cannot_be_sealed() {
        let key = [0x22; 32];
        let empty = TokenStore::empty([0x11; 16]).expect("empty store");
        assert_eq!(
            empty.seal_with_nonce(&key, [0x55; 24]),
            Err(TokenStoreError::InvalidInput)
        );
        let mut nonempty = TokenStore::empty([0x11; 16]).expect("empty store");
        nonempty.add(entry(1)).expect("add");
        assert_eq!(
            nonempty.seal_with_nonce(&key, [0; 24]),
            Err(TokenStoreError::InvalidInput)
        );
    }
}
