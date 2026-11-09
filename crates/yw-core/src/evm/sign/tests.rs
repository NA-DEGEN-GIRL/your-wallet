//! EVM signing vectors (spec/09 §3.5, 03 EVM-V01–V03, V06) and post-sign verification
//! (spec/03 §4.3, spec/09 X-17). Every signature is computed with `sign_ecdsa_recoverable`
//! (RFC 6979, no extra entropy) and compared byte for byte. The EIP-155 test follows
//! `archive/spec-v2.4:crates/key-agent/src/lib.rs:907-1051` but asserts the real RFC 6979
//! signature instead of injecting r/s.

use std::sync::{Arc, Mutex};

use secp256k1::{Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};

use super::{
    CardSignError, SignError, recover_address, recover_message_signer, sign_digest,
    sign_message_with, sign_personal, sign_personal_card, sign_transaction, sign_transaction_card,
    sign_tx_with, sign_typed_data, verify_signed_tx,
};
use crate::approval::{AccountRef, ApprovalKind, Approved, ChainRef, Signer, SigningPayload};
use crate::bip32::path::AccountIndex;
use crate::error::{StorageError, VaultError};
use crate::evm::address::{Address, parse_address};
use crate::evm::amount::U256;
use crate::evm::chain::SEPOLIA_GENESIS;
use crate::evm::eip191::{personal_digest, personal_preimage};
use crate::evm::eip712::{eip712_digest, validate_typed_data_v4};
use crate::evm::rlp::{self, decode_exact};
use crate::evm::tx::{Eip1559Tx, decode_signed, tx_hash};
use crate::hex;
use crate::password::VaultPassword;
use crate::vault::{EvmKeySource, FileKind, KdfParams, LockedSlot, SLOT_LEN, Vault, VaultStorage};

fn h(text: &str) -> Vec<u8> {
    hex::decode(text).unwrap()
}

fn h32(text: &str) -> [u8; 32] {
    hex::decode_array::<32>(text).unwrap()
}

fn key(text: &str) -> SecretKey {
    SecretKey::from_byte_array(h32(text)).unwrap()
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

fn addr(text: &str) -> Address {
    parse_address(text).unwrap()
}

// ------------------------------------------------------------ EVM-V01 EIP-155 (legacy, test only)

struct Legacy {
    nonce: u64,
    gas_price: u64,
    gas: u64,
    to: [u8; 20],
    value: U256,
    chain_id: u64,
}

fn legacy_fields(tx: &Legacy) -> Vec<u8> {
    let mut payload = Vec::new();
    rlp::encode_u64(&mut payload, tx.nonce);
    rlp::encode_u64(&mut payload, tx.gas_price);
    rlp::encode_u64(&mut payload, tx.gas);
    rlp::encode_bytes(&mut payload, &tx.to);
    rlp::encode_u256(&mut payload, &tx.value);
    rlp::encode_bytes(&mut payload, &[]);
    payload
}

fn legacy_signing_data(tx: &Legacy) -> Vec<u8> {
    let mut payload = legacy_fields(tx);
    rlp::encode_u64(&mut payload, tx.chain_id);
    rlp::encode_u64(&mut payload, 0);
    rlp::encode_u64(&mut payload, 0);
    let mut out = Vec::new();
    rlp::encode_list(&mut out, &payload);
    out
}

fn legacy_signed(tx: &Legacy, v: u64, r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut payload = legacy_fields(tx);
    rlp::encode_u64(&mut payload, v);
    rlp::encode_bytes(&mut payload, r);
    rlp::encode_bytes(&mut payload, s);
    let mut out = Vec::new();
    rlp::encode_list(&mut out, &payload);
    out
}

const EIP155_SIGNED: &str = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";

#[test]
fn evm_v01_eip155_real_rfc6979_signature() {
    let tx = Legacy {
        nonce: 9,
        gas_price: 20_000_000_000,
        gas: 21_000,
        to: [0x35; 20],
        value: U256::from_u64(1_000_000_000_000_000_000),
        chain_id: 1,
    };
    let signing_data = legacy_signing_data(&tx);
    assert_eq!(
        signing_data,
        h(
            "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080"
        )
    );
    let hash = keccak(&signing_data);
    assert_eq!(
        hash,
        h32("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53")
    );
    let ctx = Secp256k1::new();
    let secret = key("4646464646464646464646464646464646464646464646464646464646464646");
    let (recid, compact) = sign_digest(&ctx, &secret, hash).unwrap();
    let v = 35 + 2 * tx.chain_id + u64::from(recid);
    assert_eq!(v, 37);
    let (r, s) = compact.split_at(32);
    assert_eq!(
        r,
        h("28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276")
    );
    assert_eq!(
        s,
        h("67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83")
    );
    let signed = legacy_signed(&tx, v, r, s);
    assert_eq!(signed, h(EIP155_SIGNED));
    assert_eq!(
        recover_address(hash, recid, &compact),
        Some(addr("0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F"))
    );
    assert_eq!(
        tx_hash(&signed),
        h32("33469b22e9f636356c4160a87eb19df52b7412e8eac32a4a55ffe88ea8350788")
    );
}

// ------------------------------------------------------------ EVM-V02 EIP-1559 (Besu)

const BESU_SIGNED: &str = "02f86e048203338301284d8301d97c828ae094000000000000000000000000000000000000aaaa8402933bc980c080a00f924cb68412c8f1cfd74d9b581c71eeaf94fff6abdde3e5b02ca6b2931dcf47a07dd1c50027c3e31f8b565e25ce68a5072110f61fce5eee81b195dd51273c2f83";

fn besu_tx() -> Eip1559Tx {
    let mut to = [0_u8; 20];
    to[18] = 0xaa;
    to[19] = 0xaa;
    Eip1559Tx {
        chain_id: 4,
        nonce: 819,
        max_priority_fee_per_gas: U256::from_u64(75_853),
        max_fee_per_gas: U256::from_u64(121_212),
        gas_limit: 35_552,
        to: Address::from_bytes(to),
        value: U256::from_u64(43_203_529),
        data: Vec::new(),
        access_list: Vec::new(),
    }
}

#[test]
fn evm_v02_eip1559_besu_vector() {
    let tx = besu_tx();
    assert_eq!(
        tx.signing_preimage(),
        h(
            "02eb048203338301284d8301d97c828ae094000000000000000000000000000000000000aaaa8402933bc980c0"
        )
    );
    assert_eq!(
        tx.signing_hash(),
        h32("e0b52197916ca4528d05e8abfe4fd902e91dbd3137a423856228e737d984f6b2")
    );
    let ctx = Secp256k1::new();
    let secret = key("8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63");
    let sender = addr("0xFE3B557E8Fb62b89F4916B721be55cEb828dBd73");
    let signed = sign_tx_with(&ctx, &secret, &tx, &sender).unwrap();
    assert_eq!(signed.raw, h(BESU_SIGNED));
    assert_eq!(
        signed.tx_hash,
        h32("2e564c87eb4b40e7f469b2eec5aa5d18b0b46a24e8bf0919439cfb0e8fcae446")
    );
    let decoded = decode_signed(&signed.raw).unwrap();
    assert_eq!(decoded.tx, tx);
    assert_eq!(decoded.y_parity, 0);
    assert_eq!(
        decoded.r,
        h32("0f924cb68412c8f1cfd74d9b581c71eeaf94fff6abdde3e5b02ca6b2931dcf47")
    );
    assert_eq!(
        decoded.s,
        h32("7dd1c50027c3e31f8b565e25ce68a5072110f61fce5eee81b195dd51273c2f83")
    );
    let mut compact = [0_u8; 64];
    compact[..32].copy_from_slice(&decoded.r);
    compact[32..].copy_from_slice(&decoded.s);
    assert_eq!(
        recover_address(tx.signing_hash(), decoded.y_parity, &compact),
        Some(sender)
    );
    assert_eq!(decoded.encode(), signed.raw);
}

// ------------------------------------------------------------ EVM-V03 EIP-191 and EIP-712

#[test]
fn evm_v03_eip191_vectors() {
    let ctx = Secp256k1::new();
    for (secret, message, digest, signature, signer) in [
        (
            "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
            "Some data",
            "1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655",
            "b91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c",
            "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23",
        ),
        (
            "4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0",
            "Hello, world!",
            "b453bd4e271eed985cbab8231da609c4ce0a9cf1f763b6c1594e76315510e0f1",
            "90a938f7457df6e8f741264c32697fc52f9a8f867c52dd70713d9d2d472f2e415d9c94148991bbe1f4a1818d1dff09165782749c877f5cf1eff4ef126e55714d1c",
            "0x29C76e6aD8f28BB1004902578Fb108c507Be341b",
        ),
    ] {
        let computed = personal_digest(message.as_bytes());
        assert_eq!(computed, h32(digest), "{message}");
        assert_eq!(keccak(&personal_preimage(message.as_bytes())), computed);
        let signer = addr(signer);
        let produced = sign_message_with(&ctx, &key(secret), computed, &signer).unwrap();
        assert_eq!(produced.to_vec(), h(signature), "{message}");
        assert_eq!(recover_message_signer(computed, &produced), Some(signer));
    }
}

const ETHER_MAIL: &str = r#"{
  "types": {
    "EIP712Domain": [
      {"name": "name", "type": "string"},
      {"name": "version", "type": "string"},
      {"name": "chainId", "type": "uint256"},
      {"name": "verifyingContract", "type": "address"}
    ],
    "Person": [
      {"name": "name", "type": "string"},
      {"name": "wallet", "type": "address"}
    ],
    "Mail": [
      {"name": "from", "type": "Person"},
      {"name": "to", "type": "Person"},
      {"name": "contents", "type": "string"}
    ]
  },
  "primaryType": "Mail",
  "domain": {
    "name": "Ether Mail",
    "version": "1",
    "chainId": 1,
    "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
  },
  "message": {
    "from": {
      "name": "Cow",
      "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
    },
    "to": {
      "name": "Bob",
      "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
    },
    "contents": "Hello, Bob!"
  }
}"#;

#[test]
fn evm_v03_eip712_ether_mail_signature() {
    let value = yw_json::parse(ETHER_MAIL.as_bytes(), &yw_json::Limits::REQUEST).unwrap();
    let typed = validate_typed_data_v4(ETHER_MAIL.as_bytes(), &value, 1).unwrap();
    let digest = eip712_digest(&typed);
    assert_eq!(
        digest,
        h32("be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2")
    );
    let cow = keccak(b"cow");
    assert_eq!(
        cow,
        h32("c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4")
    );
    let ctx = Secp256k1::new();
    let signer = addr("0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826");
    let signature = sign_message_with(
        &ctx,
        &SecretKey::from_byte_array(cow).unwrap(),
        digest,
        &signer,
    )
    .unwrap();
    assert_eq!(
        signature[..32],
        h32("4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d")
    );
    assert_eq!(
        signature[32..64],
        h32("07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b91562")
    );
    assert_eq!(signature[64], 28);
}

// ------------------------------------------------------------ EVM-V06 strict decoding

#[test]
fn evm_v06_truncations_and_trailing_bytes_rejected() {
    let legacy = h(EIP155_SIGNED);
    assert!(decode_exact(&legacy).is_ok());
    for length in 0..legacy.len() {
        assert!(decode_exact(&legacy[..length]).is_err(), "legacy {length}");
    }
    let mut trailing = legacy.clone();
    trailing.push(0);
    assert!(decode_exact(&trailing).is_err());

    let besu = h(BESU_SIGNED);
    assert!(decode_signed(&besu).is_ok());
    for length in 0..besu.len() {
        assert!(decode_signed(&besu[..length]).is_err(), "besu {length}");
    }
    let mut trailing = besu;
    trailing.push(0);
    assert!(decode_signed(&trailing).is_err());
    // A legacy transaction is not a type-2 envelope.
    assert!(decode_signed(&legacy).is_err());
}

// ------------------------------------------------------------ X-17 post-sign verification

#[test]
fn x17_post_sign_verification_failures() {
    let ctx = Secp256k1::new();
    let tx = besu_tx();
    let sender = addr("0xFE3B557E8Fb62b89F4916B721be55cEb828dBd73");
    let raw = h(BESU_SIGNED);
    let hash = tx.signing_hash();
    assert!(verify_signed_tx(&ctx, &tx, hash, &raw, &sender).is_ok());
    // Any single-bit change of the signed bytes is rejected.
    for index in 0..raw.len() {
        for bit in [0x01_u8, 0x80] {
            let mut flipped = raw.clone();
            flipped[index] ^= bit;
            assert_eq!(
                verify_signed_tx(&ctx, &tx, hash, &flipped, &sender),
                Err(SignError::PostSignVerification),
                "byte {index} bit {bit:#x}"
            );
        }
    }
    // Signed by another key: the recovered account differs.
    let other = key("4646464646464646464646464646464646464646464646464646464646464646");
    assert_eq!(
        sign_tx_with(&ctx, &other, &tx, &sender),
        Err(SignError::PostSignVerification)
    );
    // Wrong preimage hash.
    assert_eq!(
        verify_signed_tx(&ctx, &tx, [0; 32], &raw, &sender),
        Err(SignError::PostSignVerification)
    );
    // Approved transaction differs from the signed one.
    let mut changed = tx.clone();
    changed.nonce += 1;
    assert_eq!(
        verify_signed_tx(&ctx, &changed, changed.signing_hash(), &raw, &sender),
        Err(SignError::PostSignVerification)
    );
}

// ------------------------------------------------------------ signing through the vault

const KDF_TEST: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};
const ABOUT: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[derive(Default)]
struct Mem {
    files: Vec<(FileKind, Vec<u8>)>,
}

#[derive(Clone, Default)]
struct MemStorage(Arc<Mutex<Mem>>);

impl VaultStorage for MemStorage {
    fn load(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .files
            .iter()
            .find(|(file, _)| *file == kind)
            .map(|(_, bytes)| bytes.clone()))
    }

    fn load_prev(&self, _kind: FileKind) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(None)
    }

    fn commit(
        &mut self,
        kind: FileKind,
        _expected: Option<u64>,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        let mut inner = self.0.lock().unwrap();
        inner.files.retain(|(file, _)| *file != kind);
        inner.files.push((kind, bytes.to_vec()));
        Ok(())
    }

    fn quarantine(&mut self, _kind: FileKind, _now_unix: u64) -> Result<(), StorageError> {
        Ok(())
    }
}

struct HeapSlot(Box<[u8; SLOT_LEN]>);

impl LockedSlot for HeapSlot {
    fn bytes(&self) -> &[u8; SLOT_LEN] {
        &self.0
    }

    fn bytes_mut(&mut self) -> &mut [u8; SLOT_LEN] {
        &mut self.0
    }
}

fn unlocked_vault() -> Vault {
    let mut vault = Vault::load_with_params(Box::new(MemStorage::default()), KDF_TEST).unwrap();
    vault
        .import_mnemonic(
            &VaultPassword::new(b"test password 1").unwrap(),
            ABOUT,
            None,
            Box::new(HeapSlot(Box::new([0; SLOT_LEN]))),
            1_790_000_000,
        )
        .unwrap();
    vault
}

const ACC1: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

fn sepolia_tx() -> Eip1559Tx {
    Eip1559Tx {
        chain_id: 11_155_111,
        nonce: 0,
        max_priority_fee_per_gas: U256::from_u64(100_000_000),
        max_fee_per_gas: U256::from_u64(2_000_000_000),
        gas_limit: 25_200,
        to: addr("0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0"),
        value: U256::from_u64(10_000_000_000_000_000),
        data: Vec::new(),
        access_list: Vec::new(),
    }
}

/// The card path (spec/10 §6.2) against the APDU emulator: EVM account 0 of `abandon`×11
/// `about` in `OpenPGP` SIG, high-s card signatures, full post-sign verification.
#[test]
#[allow(clippy::too_many_lines, reason = "one end-to-end scenario")]
fn card_signing_verifies_and_recovers_the_account() {
    use crate::yubikey::apdu::ApduMode;
    use crate::yubikey::mock::{MockCard, ToyCipher};
    use crate::yubikey::plan::{CardSlot, KeyRole, PgpKey, PlannedSlot};
    use crate::yubikey::sign::{CardKey, sign_evm};

    let role = KeyRole::Evm {
        index: AccountIndex::ZERO,
        btc: None,
    };
    let seed = *crate::bip39::Mnemonic::parse(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
    .unwrap()
    .to_seed(&crate::password::Bip39Passphrase::empty())
    .unwrap()
    .expose();
    let mut card = MockCard::new(42);
    let auth = crate::yubikey::enrol::EnrolAuth {
        admin_pin: b"12345678",
        management_key: &crate::yubikey::piv::DEFAULT_MANAGEMENT_KEY,
        piv_pin: b"",
        cipher: Some(&ToyCipher),
        challenge: [0; 16],
        overwrite: false,
    };
    let record = crate::yubikey::enrol::enrol_card(
        &mut card,
        ApduMode::Short,
        &seed,
        &[PlannedSlot::recommended(
            CardSlot::OpenPgp(PgpKey::Sig),
            role,
        )],
        &[],
        &auth,
    )
    .unwrap()
    .record;
    card.high_s = true;
    let key = CardKey {
        serial: 42,
        slot: record.slots[0].slot,
        public: record.slots[0].public,
    };
    let account = crate::yubikey::plan::evm_address(&key.public).unwrap();
    assert_eq!(account, addr("0x9858EfFD232B4033E47d90003D41EC34EcaEda94"));
    let ctx = Secp256k1::verification_only();
    let mut signer =
        |digest: [u8; 32]| sign_evm(&ctx, &mut card, ApduMode::Short, &key, b"123456", digest);
    let card_approved = |kind, payload| {
        Approved::for_test(
            ChainRef::Evm {
                chain_id: 11_155_111,
                genesis: SEPOLIA_GENESIS,
            },
            AccountRef::Evm(account),
            Signer::Evm(EvmKeySource::Hardware(AccountIndex::ZERO)),
            kind,
            payload,
        )
    };
    let tx = sepolia_tx();
    let card_tx = sign_transaction_card(
        card_approved(
            ApprovalKind::EvmTransaction,
            SigningPayload::EvmTx(tx.clone()),
        ),
        &mut signer,
    )
    .unwrap();
    assert_eq!(decode_signed(&card_tx.raw).unwrap().tx, tx);
    let preimage = personal_preimage(b"card");
    let signature = sign_personal_card(
        card_approved(
            ApprovalKind::EvmPersonalSign,
            SigningPayload::EvmPersonal(preimage.clone()),
        ),
        &mut signer,
    )
    .unwrap();
    assert_eq!(
        recover_message_signer(keccak(&preimage), &signature),
        Some(account)
    );
    // A vault-signer approval is refused by the card path, and a card approval by the vault path.
    let wrong = approved(
        ACC1,
        ApprovalKind::EvmPersonalSign,
        SigningPayload::EvmPersonal(preimage.clone()),
        11_155_111,
    );
    assert_eq!(
        sign_personal_card(wrong, &mut signer),
        Err(CardSignError::Sign(SignError::KindMismatch))
    );
    // Another account than the card's key fails the post-sign verification.
    let other = Approved::for_test(
        ChainRef::Evm {
            chain_id: 11_155_111,
            genesis: SEPOLIA_GENESIS,
        },
        AccountRef::Evm(addr("0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0")),
        Signer::Evm(EvmKeySource::Hardware(AccountIndex::ZERO)),
        ApprovalKind::EvmPersonalSign,
        SigningPayload::EvmPersonal(preimage),
    );
    assert_eq!(
        sign_personal_card(other, &mut signer),
        Err(CardSignError::Sign(SignError::PostSignVerification))
    );
}

fn approved(account: &str, kind: ApprovalKind, payload: SigningPayload, chain_id: u64) -> Approved {
    Approved::for_test(
        ChainRef::Evm {
            chain_id,
            genesis: SEPOLIA_GENESIS,
        },
        AccountRef::Evm(addr(account)),
        Signer::Evm(EvmKeySource::Derived(AccountIndex::ZERO)),
        kind,
        payload,
    )
}

#[test]
fn vault_signing_verifies_and_recovers_the_account() {
    let vault = unlocked_vault();
    let tx = sepolia_tx();
    let signed = sign_transaction(
        &vault,
        approved(
            ACC1,
            ApprovalKind::EvmTransaction,
            SigningPayload::EvmTx(tx.clone()),
            11_155_111,
        ),
    )
    .unwrap();
    let decoded = decode_signed(&signed.raw).unwrap();
    assert_eq!(decoded.tx, tx);
    assert_eq!(signed.tx_hash, tx_hash(&signed.raw));
    let mut compact = [0_u8; 64];
    compact[..32].copy_from_slice(&decoded.r);
    compact[32..].copy_from_slice(&decoded.s);
    assert_eq!(
        recover_address(tx.signing_hash(), decoded.y_parity, &compact),
        Some(addr(ACC1))
    );

    let preimage = personal_preimage(b"Some data");
    let signature = sign_personal(
        &vault,
        approved(
            ACC1,
            ApprovalKind::EvmPersonalSign,
            SigningPayload::EvmPersonal(preimage.clone()),
            11_155_111,
        ),
    )
    .unwrap();
    assert_eq!(
        recover_message_signer(keccak(&preimage), &signature),
        Some(addr(ACC1))
    );
    assert!(signature[64] == 27 || signature[64] == 28);

    let mut typed = [0_u8; 66];
    typed[0] = 0x19;
    typed[1] = 0x01;
    let signature = sign_typed_data(
        &vault,
        approved(
            ACC1,
            ApprovalKind::EvmTypedData,
            SigningPayload::EvmTypedData(typed),
            11_155_111,
        ),
    )
    .unwrap();
    assert_eq!(
        recover_message_signer(keccak(&typed), &signature),
        Some(addr(ACC1))
    );
}

#[test]
fn vault_signing_rejects_mismatches() {
    let vault = unlocked_vault();
    let tx = sepolia_tx();
    // Payload/kind mismatches never reach the key.
    assert_eq!(
        sign_transaction(
            &vault,
            approved(
                ACC1,
                ApprovalKind::EvmPersonalSign,
                SigningPayload::EvmTx(tx.clone()),
                11_155_111
            )
        ),
        Err(SignError::KindMismatch)
    );
    assert_eq!(
        sign_transaction(
            &vault,
            approved(
                ACC1,
                ApprovalKind::EvmTransaction,
                SigningPayload::EvmPersonal(vec![1]),
                11_155_111
            )
        ),
        Err(SignError::KindMismatch)
    );
    assert_eq!(
        sign_transaction(
            &vault,
            approved(
                ACC1,
                ApprovalKind::EvmTransaction,
                SigningPayload::EvmTx(tx.clone()),
                1
            )
        ),
        Err(SignError::KindMismatch)
    );
    assert_eq!(
        sign_personal(
            &vault,
            approved(
                ACC1,
                ApprovalKind::EvmTypedData,
                SigningPayload::EvmPersonal(vec![1]),
                11_155_111
            )
        ),
        Err(SignError::KindMismatch)
    );
    assert_eq!(
        sign_typed_data(
            &vault,
            approved(
                ACC1,
                ApprovalKind::EvmPersonalSign,
                SigningPayload::EvmTypedData([0; 66]),
                11_155_111
            )
        ),
        Err(SignError::KindMismatch)
    );
    // The approved account is not the key's account (ACC-2): post-sign verification fails.
    assert_eq!(
        sign_transaction(
            &vault,
            approved(
                "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0",
                ApprovalKind::EvmTransaction,
                SigningPayload::EvmTx(tx),
                11_155_111
            )
        ),
        Err(SignError::PostSignVerification)
    );
}

#[test]
fn locked_vault_refuses_to_sign() {
    let mut vault = unlocked_vault();
    vault.lock();
    let result = sign_personal(
        &vault,
        approved(
            ACC1,
            ApprovalKind::EvmPersonalSign,
            SigningPayload::EvmPersonal(personal_preimage(b"x")),
            11_155_111,
        ),
    );
    assert!(
        matches!(result, Err(SignError::Vault(VaultError::InvalidState))),
        "{result:?}"
    );
}

#[test]
fn invalid_transaction_is_never_signed() {
    let vault = unlocked_vault();
    let mut tx = sepolia_tx();
    tx.max_priority_fee_per_gas = U256::from_u64(3_000_000_000);
    assert_eq!(
        sign_transaction(
            &vault,
            approved(
                ACC1,
                ApprovalKind::EvmTransaction,
                SigningPayload::EvmTx(tx),
                11_155_111
            )
        ),
        Err(SignError::KindMismatch)
    );
}

#[test]
fn message_preimages_need_their_exact_prefixes() {
    use super::{is_personal_preimage, is_typed_data_preimage};
    assert!(is_personal_preimage(&personal_preimage(b"")));
    assert!(is_personal_preimage(&personal_preimage(b"Some data")));
    // A message that starts with digits still has exactly one valid split.
    assert!(is_personal_preimage(&personal_preimage(b"12345678901")));
    assert!(is_personal_preimage(&personal_preimage(&vec![7; 65_536])));
    assert!(!is_personal_preimage(&personal_preimage(&vec![7; 65_537])));
    for bad in [
        b"\x19Ethereum Signed Message:\n10Some data".as_slice(),
        b"\x19Ethereum Signed Message:\n09Some data".as_slice(),
        b"\x19Ethereum Signed Message:\nSome data".as_slice(),
        b"\x19Ethereum Signed Message:\n".as_slice(),
        b"\x19Ethereum Signed Message:\r9Some data".as_slice(),
        b"Ethereum Signed Message:\n9Some data".as_slice(),
        &[0xab; 32],
        &[0x19, 0x01, 0, 0],
    ] {
        assert!(!is_personal_preimage(bad), "{bad:?}");
    }
    let mut typed = [0_u8; 66];
    typed[0] = 0x19;
    typed[1] = 0x01;
    assert!(is_typed_data_preimage(&typed));
    typed[1] = 0x00;
    assert!(!is_typed_data_preimage(&typed));
    assert!(!is_typed_data_preimage(&[0; 66]));

    // Signing refuses them before the key is used.
    let vault = unlocked_vault();
    assert_eq!(
        sign_personal(
            &vault,
            approved(
                ACC1,
                ApprovalKind::EvmPersonalSign,
                SigningPayload::EvmPersonal(vec![0xab; 32]),
                11_155_111
            )
        ),
        Err(SignError::KindMismatch)
    );
    assert_eq!(
        sign_personal(
            &vault,
            approved(
                ACC1,
                ApprovalKind::EvmPersonalSign,
                SigningPayload::EvmPersonal(b"\x19Ethereum Signed Message:\n10Some data".to_vec()),
                11_155_111
            )
        ),
        Err(SignError::KindMismatch)
    );
    assert_eq!(
        sign_typed_data(
            &vault,
            approved(
                ACC1,
                ApprovalKind::EvmTypedData,
                SigningPayload::EvmTypedData([0; 66]),
                11_155_111
            )
        ),
        Err(SignError::KindMismatch)
    );
}

/// `HyperCore 전송` end to end for every action kind (spec/11 §9): the app-built draft is issued
/// and consumed by the store, the vault signs the action's preimage, and the signature recovers to
/// the account; a draft whose chain does not match the action is refused at issue.
#[test]
fn hypercore_actions_through_the_approval_store() {
    use crate::approval::{ApprovalId, ApprovalStore};
    use crate::hypercore::display::{HcApprovalInput, HcRecipient, build_hypercore_request};
    use crate::hypercore::{HcAction, HcNetwork, HcPayload, system_address};

    let vault = unlocked_vault();
    let account = addr(ACC1);
    let destination = addr("0x5e9ee1089755c3435139848e47e6635505d5a13a");
    let purr = "PURR:0xc4bf3f870c0e9465323c0b6ed28096c2".to_owned();
    let payloads = [
        HcPayload::UsdSend {
            destination,
            amount: "1".to_owned(),
        },
        HcPayload::SpotSend {
            destination,
            token: purr.clone(),
            amount: "0.5".to_owned(),
        },
        HcPayload::Withdraw {
            destination: account,
            amount: "5".to_owned(),
        },
        HcPayload::UsdClassTransfer {
            amount: "2".to_owned(),
            to_perp: false,
        },
        HcPayload::SendAsset {
            destination: system_address(1),
            source_dex: "spot".to_owned(),
            destination_dex: "spot".to_owned(),
            token: purr,
            amount: "0.25".to_owned(),
        },
    ];
    let mut store = ApprovalStore::new();
    for (index, payload) in (1_u8..).zip(payloads) {
        let action = HcAction::new(HcNetwork::Testnet, 1_790_000_000_000, payload);
        let input = HcApprovalInput {
            action: &action,
            account,
            signer: EvmKeySource::Derived(AccountIndex::new(0).unwrap()),
            token: None,
            recipient: HcRecipient {
                notes: vec!["주소록에 없는 주소입니다.".to_owned()],
                look_alike: false,
                not_in_book: true,
            },
        };
        let draft = build_hypercore_request(ApprovalId([index; 16]), &input).unwrap();
        assert_eq!(draft.kind, ApprovalKind::HyperCoreAction);
        let request = store.issue(draft.clone(), 0, 1_790_000_000_000).unwrap();
        let approved = store.consume(request.id, request.digest, 1).unwrap();
        let signature = sign_typed_data(&vault, approved).unwrap();
        assert_eq!(
            recover_message_signer(action.digest(), &signature),
            Some(account)
        );

        // A chain that does not match the action is a payload mismatch.
        let mut wrong = draft;
        wrong.id = ApprovalId([index | 0x80; 16]);
        wrong.chain = ChainRef::HyperCore {
            network: HcNetwork::Mainnet.code(),
            signature_chain_id: action.signature_chain_id,
        };
        assert!(store.issue(wrong, 0, 1_790_000_000_000).is_err());
    }
}
