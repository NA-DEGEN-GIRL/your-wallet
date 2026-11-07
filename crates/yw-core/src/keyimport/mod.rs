//! Imported private keys (D9, spec/02 §8.4): the export formats of the three chains parsed into a
//! secret-bearing [`ImportKey`], and the public preview of each (the address the user confirms
//! before anything is stored).
//!
//! | Chain | Accepted text |
//! |---|---|
//! | EVM | optional `0x` + 64 hex (spec/02 §8.2) |
//! | Solana | base58 64-byte keypair (Phantom/Solflare) or `solana-keygen` JSON array of 64 numbers |
//! | Bitcoin | WIF (mainnet `0x80` / test `0xef` → testnet4, compressed or not) + a chosen address type |
//! | Zcash | compressed WIF (`0x80` mainnet / `0xef` testnet, must be the chosen network) or 64 hex with the chosen network; one P2PKH address |
//!
//! Every parser ignores surrounding ASCII whitespace, accepts ASCII only, keeps decoded secrets in
//! `Zeroizing` buffers and never echoes input in errors. A Bitcoin key's address type is the
//! account [`ScriptType`] of `btc::account` (same stable codes 1–4 in the vault record), and its
//! output and address come from the same code as every other Bitcoin account
//! (`btc::account::kind_for_key`, BIP86 tweak in `btc::taproot`).
#![deny(clippy::indexing_slicing)]

use core::fmt;

use secp256k1::{PublicKey, SecretKey};
use zeroize::Zeroizing;

pub(crate) mod sol;

pub use sol::SOL_KEY_TEXT_MAX;

use crate::btc::account::{AccountKeyError, BtcAccountKey, BtcPubKey, ScriptType, kind_for_key};
use crate::btc::address::{ScriptKind, encode_address};
use crate::btc::network::BtcNetwork;
use crate::codec::wif::parse_wif;
use crate::entropy::{OsRandom, secp_context};
use crate::error::KeyError;
use crate::evm::Address;
use crate::hex;
use crate::sol::SolAddress;
use crate::zec::ZecNetwork;

/// Imported keys per chain (spec/02 §4.6, §5.3).
pub const MAX_IMPORTED_PER_CHAIN: usize = 15;

/// The chain of an imported key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ImportChain {
    /// EVM (`tag 2`).
    Evm,
    /// Solana (`tag 3`).
    Sol,
    /// Bitcoin (`tag 4`).
    Btc,
    /// Zcash transparent (`tag 6`, spec/12 §2.3).
    Zec,
}

impl ImportChain {
    /// The user-facing chain name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Evm => "EVM",
            Self::Sol => "Solana",
            Self::Btc => "Bitcoin",
            Self::Zec => "Zcash",
        }
    }
}

/// What is being imported: the chain, and for Bitcoin the chosen address type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ImportSpec {
    /// EVM hex key.
    Evm,
    /// Solana keypair.
    Sol,
    /// Bitcoin WIF used as this address type.
    Btc(ScriptType),
    /// Zcash compressed WIF or hex key of this network.
    Zec(ZecNetwork),
}

impl ImportSpec {
    /// The chain.
    #[must_use]
    pub const fn chain(self) -> ImportChain {
        match self {
            Self::Evm => ImportChain::Evm,
            Self::Sol => ImportChain::Sol,
            Self::Btc(_) => ImportChain::Btc,
            Self::Zec(_) => ImportChain::Zec,
        }
    }
}

/// The parsed secret of an import (crate-internal layout; only the vault reads it).
pub(crate) enum ImportInner {
    Evm(Zeroizing<[u8; 32]>),
    Sol {
        seed: Zeroizing<[u8; 32]>,
        public: [u8; 32],
    },
    Btc {
        secret: Zeroizing<[u8; 32]>,
        compressed: bool,
        network: BtcNetwork,
        script: ScriptType,
    },
    Zec {
        secret: Zeroizing<[u8; 32]>,
        network: ZecNetwork,
    },
}

/// A parsed private key ready for [`crate::vault::Vault::import_key`] or
/// [`crate::vault::Vault::create_with_key`]. Not `Clone`; `Debug` is redacted; the secret is
/// wiped on drop.
pub struct ImportKey {
    pub(crate) inner: ImportInner,
}

impl fmt::Debug for ImportKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ImportKey({:?}, [REDACTED])", self.chain())
    }
}

/// Public facts of an imported Bitcoin key (preview, listing, and its Bitcoin account).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcKeyInfo {
    /// Network of the WIF version byte.
    pub network: BtcNetwork,
    /// Chosen address type.
    pub script: ScriptType,
    /// The public key is used compressed.
    pub compressed: bool,
    /// The public key as used (33 bytes compressed, 65 uncompressed).
    pub public_key: BtcPubKey,
    /// Output script kind (hash/program/output key).
    pub kind: ScriptKind,
    /// Address string on `network`.
    pub address: String,
}

impl BtcKeyInfo {
    /// The Bitcoin account of this key stored as vault record `id` (spec/08 §3.5: one address,
    /// change back to it, no gap scan).
    ///
    /// # Errors
    ///
    /// [`AccountKeyError::UncompressedNotP2pkh`] (never for a parsed key).
    pub const fn account_key(&self, id: [u8; 16]) -> Result<BtcAccountKey, AccountKeyError> {
        BtcAccountKey::single(id, self.script, self.public_key)
    }
}

/// Public facts of an imported Zcash transparent key (spec/12 §2.3): one P2PKH address of the
/// compressed public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZecKeyInfo {
    /// Network.
    pub network: ZecNetwork,
    /// Compressed public key.
    pub pubkey: [u8; 33],
    /// `t1…` / `tm…` address.
    pub address: String,
}

impl ZecKeyInfo {
    /// The Zcash account of this key.
    #[must_use]
    pub const fn account(&self) -> crate::zec::ZecAccount {
        crate::zec::ZecAccount {
            network: self.network,
            source: crate::zec::ZecKeySource::Imported,
            pubkey: self.pubkey,
        }
    }
}

/// What the user confirms before an import is stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportPreview {
    /// EVM address.
    Evm(Address),
    /// Solana address (= public key).
    Sol(SolAddress),
    /// Bitcoin address and its facts.
    Btc(BtcKeyInfo),
    /// Zcash address and its facts.
    Zec(ZecKeyInfo),
}

/// The facts of a Zcash key (compressed public key, P2PKH address on `network`).
pub(crate) fn zec_info(secret: &[u8; 32], network: ZecNetwork) -> Result<ZecKeyInfo, KeyError> {
    let ctx = secp_context(&mut OsRandom)?;
    let mut key = SecretKey::from_byte_array(*secret).map_err(|_| KeyError::InvalidPrivateKey)?;
    let pubkey = PublicKey::from_secret_key(&ctx, &key).serialize();
    key.non_secure_erase();
    let account = crate::zec::ZecAccount {
        network,
        source: crate::zec::ZecKeySource::Imported,
        pubkey,
    };
    Ok(ZecKeyInfo {
        network,
        pubkey,
        address: account.address(),
    })
}

/// A Zcash private key (spec/12 §2.3, §16 #2): a compressed WIF whose version is `network`'s
/// (`0x80` mainnet, `0xEF` testnet), or 64 hex digits (optional `0x`) used on `network`.
/// Uncompressed WIF is refused (the account uses the compressed key).
fn parse_zec_key(text: &str, network: ZecNetwork) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let text = trim_blank(text);
    if !text.is_ascii() {
        return Err(KeyError::ZecKeyFormat);
    }
    let digits = text.strip_prefix("0x").unwrap_or(text);
    if digits.len() == 64 {
        let mut key = Zeroizing::new([0_u8; 32]);
        hex::decode_into(digits.as_bytes(), key.as_mut(), true)
            .map_err(|_| KeyError::ZecKeyFormat)?;
        let mut check = SecretKey::from_byte_array(*key).map_err(|_| KeyError::ZecKeyFormat)?;
        check.non_secure_erase();
        return Ok(key);
    }
    let wif = parse_wif(text).map_err(|_| KeyError::ZecKeyFormat)?;
    if !wif.compressed() {
        return Err(KeyError::ZecKeyFormat);
    }
    let wif_network = match wif.network() {
        BtcNetwork::Mainnet => ZecNetwork::Mainnet,
        BtcNetwork::Testnet4 => ZecNetwork::Testnet,
    };
    if wif_network != network {
        return Err(KeyError::ZecKeyNetwork);
    }
    let mut secret = Zeroizing::new([0_u8; 32]);
    secret.copy_from_slice(wif.secret().as_slice());
    Ok(secret)
}

/// Optional lowercase `0x` + exactly 64 hex digits, value in [1, n−1] (spec/02 §8.2).
pub(crate) fn parse_evm_private_key(text: &str) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    let mut key = Zeroizing::new([0_u8; 32]);
    hex::decode_into(digits.as_bytes(), key.as_mut(), true)
        .map_err(|_| KeyError::InvalidPrivateKey)?;
    let mut check = SecretKey::from_byte_array(*key).map_err(|_| KeyError::InvalidPrivateKey)?;
    check.non_secure_erase();
    Ok(key)
}

fn trim_blank(text: &str) -> &str {
    text.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\r' | '\n'))
}

/// The facts of a Bitcoin key: public key, output kind and address, computed like every
/// Bitcoin account's ([`kind_for_key`]: HASH160 for P2PKH / P2SH-P2WPKH / P2WPKH, the BIP86
/// key-path output key for P2TR).
pub(crate) fn btc_info(
    secret: &[u8; 32],
    compressed: bool,
    network: BtcNetwork,
    script: ScriptType,
) -> Result<BtcKeyInfo, KeyError> {
    if !compressed && script != ScriptType::P2pkh {
        return Err(KeyError::WifUncompressedScript);
    }
    let ctx = secp_context(&mut OsRandom)?;
    let mut key = SecretKey::from_byte_array(*secret).map_err(|_| KeyError::InvalidPrivateKey)?;
    let public = PublicKey::from_secret_key(&ctx, &key);
    key.non_secure_erase();
    let public_key = BtcPubKey::of_point(&public, compressed);
    let kind = kind_for_key(&ctx, script, &public_key)?;
    Ok(BtcKeyInfo {
        network,
        script,
        compressed,
        public_key,
        address: encode_address(&kind, network),
        kind,
    })
}

impl ImportKey {
    /// Parses `text` for `spec` (surrounding ASCII whitespace ignored).
    ///
    /// # Errors
    ///
    /// EVM [`KeyError::InvalidPrivateKey`]; Solana [`KeyError::SolKeyFormat`],
    /// [`KeyError::SolKeyIsAddress`], [`KeyError::SolKeyMismatch`]; Bitcoin
    /// [`KeyError::WifFormat`], [`KeyError::WifUncompressedScript`]; Zcash
    /// [`KeyError::ZecKeyFormat`], [`KeyError::ZecKeyNetwork`].
    pub fn parse(spec: ImportSpec, text: &str) -> Result<Self, KeyError> {
        let inner = match spec {
            ImportSpec::Evm => {
                let text = trim_blank(text);
                if !text.is_ascii() {
                    return Err(KeyError::InvalidPrivateKey);
                }
                ImportInner::Evm(parse_evm_private_key(text)?)
            }
            ImportSpec::Sol => {
                let parsed = sol::parse_sol_secret(text)?;
                ImportInner::Sol {
                    seed: parsed.seed,
                    public: parsed.public,
                }
            }
            ImportSpec::Btc(script) => {
                let wif = parse_wif(text)?;
                // Segwit and Taproot need a compressed (or x-only) key (spec/08 §3.5).
                if !wif.compressed() && script != ScriptType::P2pkh {
                    return Err(KeyError::WifUncompressedScript);
                }
                let mut secret = Zeroizing::new([0_u8; 32]);
                secret.copy_from_slice(wif.secret().as_slice());
                ImportInner::Btc {
                    secret,
                    compressed: wif.compressed(),
                    network: wif.network(),
                    script,
                }
            }
            ImportSpec::Zec(network) => ImportInner::Zec {
                secret: parse_zec_key(text, network)?,
                network,
            },
        };
        Ok(Self { inner })
    }

    /// The chain.
    #[must_use]
    pub const fn chain(&self) -> ImportChain {
        match self.inner {
            ImportInner::Evm(_) => ImportChain::Evm,
            ImportInner::Sol { .. } => ImportChain::Sol,
            ImportInner::Btc { .. } => ImportChain::Btc,
            ImportInner::Zec { .. } => ImportChain::Zec,
        }
    }

    /// The address the user confirms (computed from the secret; nothing is stored).
    ///
    /// # Errors
    ///
    /// [`KeyError::RandomnessUnavailable`] (secp context) or [`KeyError::DerivationFailed`].
    pub fn preview(&self) -> Result<ImportPreview, KeyError> {
        match &self.inner {
            ImportInner::Evm(key) => {
                let ctx = secp_context(&mut OsRandom)?;
                let mut secret =
                    SecretKey::from_byte_array(**key).map_err(|_| KeyError::InvalidPrivateKey)?;
                let public = PublicKey::from_secret_key(&ctx, &secret);
                secret.non_secure_erase();
                Ok(ImportPreview::Evm(Address::from_public_key(&public)))
            }
            ImportInner::Sol { public, .. } => {
                Ok(ImportPreview::Sol(SolAddress::from_bytes(*public)))
            }
            ImportInner::Btc {
                secret,
                compressed,
                network,
                script,
            } => Ok(ImportPreview::Btc(btc_info(
                secret,
                *compressed,
                *network,
                *script,
            )?)),
            ImportInner::Zec { secret, network } => {
                Ok(ImportPreview::Zec(zec_info(secret, *network)?))
            }
        }
    }
}

#[cfg(test)]
mod tests;
