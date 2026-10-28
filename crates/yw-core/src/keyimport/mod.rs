//! Imported private keys (D9, spec/02 §8.4): the export formats of the three chains parsed into a
//! secret-bearing [`ImportKey`], and the public preview of each (the address the user confirms
//! before anything is stored).
//!
//! | Chain | Accepted text |
//! |---|---|
//! | EVM | optional `0x` + 64 hex (spec/02 §8.2) |
//! | Solana | base58 64-byte keypair (Phantom/Solflare) or `solana-keygen` JSON array of 64 numbers |
//! | Bitcoin | WIF (mainnet `0x80` / test `0xef` → testnet4, compressed or not) + a chosen script type |
//!
//! Every parser ignores surrounding ASCII whitespace, accepts ASCII only, keeps decoded secrets in
//! `Zeroizing` buffers and never echoes input in errors.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use secp256k1::{PublicKey, SecretKey};
use zeroize::Zeroizing;

pub mod btc;
pub(crate) mod sol;

pub use btc::BtcScriptType;
pub use sol::SOL_KEY_TEXT_MAX;

use crate::btc::address::ScriptKind;
use crate::btc::network::BtcNetwork;
use crate::codec::wif::parse_wif;
use crate::entropy::{OsRandom, secp_context};
use crate::error::KeyError;
use crate::evm::Address;
use crate::hex;
use crate::sol::SolAddress;

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
}

impl ImportChain {
    /// The user-facing chain name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Evm => "EVM",
            Self::Sol => "Solana",
            Self::Btc => "Bitcoin",
        }
    }
}

/// What is being imported: the chain, and for Bitcoin the chosen script type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ImportSpec {
    /// EVM hex key.
    Evm,
    /// Solana keypair.
    Sol,
    /// Bitcoin WIF used as this script type.
    Btc(BtcScriptType),
}

impl ImportSpec {
    /// The chain.
    #[must_use]
    pub const fn chain(self) -> ImportChain {
        match self {
            Self::Evm => ImportChain::Evm,
            Self::Sol => ImportChain::Sol,
            Self::Btc(_) => ImportChain::Btc,
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
        script: BtcScriptType,
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

/// Public facts of an imported Bitcoin key (preview and listing).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcKeyInfo {
    /// Network of the WIF version byte.
    pub network: BtcNetwork,
    /// Chosen script type.
    pub script: BtcScriptType,
    /// The public key is used compressed.
    pub compressed: bool,
    /// The public key as used (33 bytes compressed, 65 uncompressed).
    pub public_key: Vec<u8>,
    /// Output script kind (hash/program/output key).
    pub kind: ScriptKind,
    /// Address string on `network`.
    pub address: String,
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

/// The facts of a Bitcoin key: public key, script kind, address.
pub(crate) fn btc_info(
    secret: &[u8; 32],
    compressed: bool,
    network: BtcNetwork,
    script: BtcScriptType,
) -> Result<BtcKeyInfo, KeyError> {
    let ctx = secp_context(&mut OsRandom)?;
    let mut key = SecretKey::from_byte_array(*secret).map_err(|_| KeyError::InvalidPrivateKey)?;
    let public = PublicKey::from_secret_key(&ctx, &key);
    key.non_secure_erase();
    let kind = btc::script_kind(&ctx, &public, compressed, script)?;
    Ok(BtcKeyInfo {
        network,
        script,
        compressed,
        public_key: if compressed {
            public.serialize().to_vec()
        } else {
            public.serialize_uncompressed().to_vec()
        },
        address: crate::btc::address::encode_address(&kind, network),
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
    /// [`KeyError::WifFormat`], [`KeyError::WifUncompressedScript`].
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
                if !wif.compressed() && !script.allows_uncompressed() {
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
        }
    }
}

#[cfg(test)]
mod tests;
