//! ACC-1–5 (spec/09 §3.4, spec/02 §11.4). ACC-1/2/5 port
//! `archive/spec-v2.4:demo/sepolia-wallet/src/wallet_secret.rs:964-998,1080-1096`.

use secp256k1::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use super::{Address, AddressError, parse_address};
use crate::bip32::path::{AccountIndex, evm_path};
use crate::bip32::{evm_address_from_seed, preview_evm_address, secret_key_from_seed};
use crate::bip39::Mnemonic;
use crate::entropy::{OsRandom, secp_context};
use crate::error::KeyError;
use crate::hex;
use crate::password::Bip39Passphrase;

const ABOUT: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn index(i: u32) -> AccountIndex {
    AccountIndex::new(i).unwrap()
}

fn account(phrase: &str, passphrase: &str, i: u32) -> (String, String) {
    let ctx = secp_context(&mut OsRandom).unwrap();
    let seed = Mnemonic::parse(phrase)
        .unwrap()
        .to_seed(&Bip39Passphrase::new(passphrase).unwrap());
    let mut secret = secret_key_from_seed(&ctx, &seed, &evm_path(index(i))).unwrap();
    let key = hex::encode(&secret.secret_bytes());
    secret.non_secure_erase();
    let address = evm_address_from_seed(&ctx, &seed, index(i)).unwrap();
    (address.to_checksum(), key)
}

#[test]
fn acc_1_2_about_accounts_0_and_1() {
    assert_eq!(
        account(ABOUT, "", 0),
        (
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94".to_owned(),
            "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727".to_owned()
        )
    );
    assert_eq!(
        account(ABOUT, "", 1),
        (
            "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0".to_owned(),
            "9a983cb3d832fbde5ab49d692b7a8bf5b5d232479c99333d0fc8e1d21f1b55b6".to_owned()
        )
    );
}

#[test]
fn acc_3_art_accounts_0_and_1() {
    let art = Mnemonic::from_entropy(&[0; 32]).unwrap().phrase();
    assert_eq!(
        account(&art, "", 0),
        (
            "0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb".to_owned(),
            "1053fae1b3ac64f178bcc21026fd06a3f4544ec2f35338b001f02d1d8efa3d5f".to_owned()
        )
    );
    assert_eq!(
        account(&art, "", 1),
        (
            "0xf785bD075874b8423D3583728a981399f31e95aA".to_owned(),
            "0855b75d03a8830e390b5483d81694c9c7121d971e092145cf8b9c6fa3a5b373".to_owned()
        )
    );
}

#[test]
fn acc_4_trezor_passphrase_and_check_value() {
    let (address, _) = account(ABOUT, "TREZOR", 0);
    assert_eq!(address, "0x9c32F71D4DB8Fb9e1A58B0a80dF79935e7256FA6");
    let parsed = parse_address(&address).unwrap();
    let check = Sha256::digest(parsed.as_bytes());
    assert_eq!(hex::encode(check.get(..4).unwrap()), "dc929830");
}

#[test]
fn acc_5_raw_key_one() {
    let ctx = secp_context(&mut OsRandom).unwrap();
    let mut bytes = [0_u8; 32];
    bytes[31] = 1;
    let mut secret = SecretKey::from_byte_array(bytes).unwrap();
    let address = Address::from_public_key(&PublicKey::from_secret_key(&ctx, &secret));
    secret.non_secure_erase();
    assert_eq!(
        address.to_checksum(),
        "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
    );
    assert_eq!(
        address.to_lower_hex(),
        "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    );
    assert_eq!(
        format!("{address:?}"),
        "Address(0x7e5f4552091a69125d5dfcb7b8c2659029395bdf)"
    );
}

#[test]
fn preview_matches_vault_free_derivation() {
    let trezor = Bip39Passphrase::new("TREZOR").unwrap();
    assert_eq!(
        preview_evm_address(ABOUT, None, index(0))
            .unwrap()
            .to_checksum(),
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    );
    assert_eq!(
        preview_evm_address(ABOUT, Some(&trezor), index(0))
            .unwrap()
            .to_checksum(),
        "0x9c32F71D4DB8Fb9e1A58B0a80dF79935e7256FA6"
    );
    assert_eq!(
        preview_evm_address(ABOUT, Some(&Bip39Passphrase::empty()), index(0)).err(),
        Some(KeyError::PassphraseEmpty)
    );
    assert_eq!(
        preview_evm_address(&["abandon"; 12].join(" "), None, index(0)).err(),
        Some(KeyError::MnemonicChecksum)
    );
}

#[test]
fn parse_rejects_uppercase_prefix() {
    assert_eq!(
        parse_address("0X9858EfFD232B4033E47d90003D41EC34EcaEda94"),
        Err(AddressError::InvalidFormat)
    );
}
