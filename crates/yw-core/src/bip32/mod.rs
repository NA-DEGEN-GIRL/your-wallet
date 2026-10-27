//! BIP32 secp256k1 derivation (spec/02 §3.1–§3.4).
//!
//! Ported from `archive/spec-v2.4:crates/secret-core/src/bip32.rs` (path parser, `from_seed`,
//! `derive_child`, `hmac_sha512`) with invalid-child skipping removed: an invalid child is
//! `KeyError::DerivationFailed`, never the next index. Public derivation (`AccountXpub`,
//! `derive_public_child`) is added with Bitcoin (M8).

use core::fmt;
use core::str::FromStr;

use hmac::{Hmac, Mac};
use secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

use crate::bip39::Mnemonic;
use crate::entropy::{OsRandom, secp_context};
use crate::error::KeyError;
use crate::evm::Address;
use crate::password::Bip39Passphrase;

pub mod path;
pub mod xkey;

use path::{AccountIndex, evm_path};

/// Bit 31 marks a hardened child number.
pub const HARDENED: u32 = 0x8000_0000;
/// Maximum path depth.
pub const MAX_PATH_DEPTH: usize = 10;
/// HMAC key for the master node.
pub const BIP32_ROOT_KEY: &[u8] = b"Bitcoin seed";

type HmacSha512 = Hmac<Sha512>;

/// A strictly parsed absolute path: `m` or `m/` components, depth 0–10, bit 31 = hardened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bip32Path {
    components: Vec<u32>,
}

impl Bip32Path {
    /// The master path `m`.
    #[must_use]
    pub const fn master() -> Self {
        Self {
            components: Vec::new(),
        }
    }

    pub(crate) fn from_components(components: Vec<u32>) -> Result<Self, KeyError> {
        if components.len() > MAX_PATH_DEPTH {
            return Err(KeyError::InvalidPath);
        }
        Ok(Self { components })
    }

    /// Child numbers; bit 31 marks hardened derivation.
    #[must_use]
    pub fn components(&self) -> &[u32] {
        &self.components
    }

    /// Path depth.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.components.len()
    }
}

fn parse_component(component: &str) -> Result<u32, KeyError> {
    let (digits, hardened) = component
        .strip_suffix('\'')
        .map_or((component, false), |digits| (digits, true));
    let canonical = !digits.is_empty()
        && digits.len() <= 10
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'));
    if !canonical {
        return Err(KeyError::InvalidPath);
    }
    let value = digits.parse::<u32>().map_err(|_| KeyError::InvalidPath)?;
    if value >= HARDENED {
        return Err(KeyError::InvalidPath);
    }
    Ok(if hardened { value | HARDENED } else { value })
}

impl FromStr for Bip32Path {
    type Err = KeyError;

    /// Grammar: `"m"` or `"m/" comp ("/" comp)*`, `comp = ("0" | [1-9][0-9]*) "'"?`, value < 2^31.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input == "m" {
            return Ok(Self::master());
        }
        let rest = input.strip_prefix("m/").ok_or(KeyError::InvalidPath)?;
        let components = rest
            .split('/')
            .map(parse_component)
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_components(components)
    }
}

impl fmt::Display for Bip32Path {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("m")?;
        for component in &self.components {
            let value = component & !HARDENED;
            if component & HARDENED == 0 {
                write!(formatter, "/{value}")?;
            } else {
                write!(formatter, "/{value}'")?;
            }
        }
        Ok(())
    }
}

/// An extended private key node. Secret: zeroized on drop, redacted `Debug`.
pub(crate) struct XPriv {
    key: Zeroizing<[u8; 32]>,
    chain_code: Zeroizing<[u8; 32]>,
    depth: u8,
    child_number: u32,
}

impl fmt::Debug for XPriv {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XPriv([REDACTED])")
    }
}

/// `HMAC-SHA512(key, parts…)` into a zeroizing buffer.
pub(crate) fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> Result<Zeroizing<[u8; 64]>, KeyError> {
    let mut mac = HmacSha512::new_from_slice(key).map_err(|_| KeyError::Internal)?;
    for part in parts {
        mac.update(part);
    }
    let mut digest = mac.finalize().into_bytes();
    let mut out = Zeroizing::new([0_u8; 64]);
    out.copy_from_slice(digest.as_slice());
    digest.as_mut_slice().zeroize();
    Ok(out)
}

pub(crate) fn split_halves(output: &[u8; 64]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mut left = Zeroizing::new([0_u8; 32]);
    let mut right = Zeroizing::new([0_u8; 32]);
    let (il, ir) = output.split_at(32);
    left.copy_from_slice(il);
    right.copy_from_slice(ir);
    (left, right)
}

/// `k_i = parse256(IL) + k_par (mod n)`; IL ≥ n or a zero result is `DerivationFailed` (no skipping).
pub(crate) fn ckd_from_il(
    parent_key: &[u8; 32],
    il: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let mut tweak = Scalar::from_be_bytes(*il).map_err(|_| KeyError::DerivationFailed)?;
    let mut parent = SecretKey::from_byte_array(*parent_key).map_err(|_| KeyError::Internal)?;
    let child = parent.add_tweak(&tweak);
    parent.non_secure_erase();
    tweak.non_secure_erase();
    let mut child = child.map_err(|_| KeyError::DerivationFailed)?;
    let out = Zeroizing::new(child.secret_bytes());
    child.non_secure_erase();
    Ok(out)
}

impl XPriv {
    /// Master node: `I = HMAC-SHA512("Bitcoin seed", seed)`; IL = 0 or IL ≥ n is `DerivationFailed`.
    pub(crate) fn from_seed(seed: &[u8]) -> Result<Self, KeyError> {
        if !(16..=64).contains(&seed.len()) {
            return Err(KeyError::InvalidEntropyLength);
        }
        let output = hmac_sha512(BIP32_ROOT_KEY, &[seed])?;
        let (key, chain_code) = split_halves(&output);
        let mut check = SecretKey::from_byte_array(*key).map_err(|_| KeyError::DerivationFailed)?;
        check.non_secure_erase();
        Ok(Self {
            key,
            chain_code,
            depth: 0,
            child_number: 0,
        })
    }

    /// `CKDpriv`. Hardened: `0x00 ‖ ser256(k) ‖ ser32(i)`; normal: `serP(K) ‖ ser32(i)`.
    pub(crate) fn derive_child(&self, ctx: &Secp256k1<All>, index: u32) -> Result<Self, KeyError> {
        let depth = self.depth.checked_add(1).ok_or(KeyError::InvalidPath)?;
        let index_bytes = index.to_be_bytes();
        let output = if index & HARDENED == 0 {
            let public = self.public_key(ctx)?.serialize();
            hmac_sha512(self.chain_code.as_slice(), &[&public, &index_bytes])?
        } else {
            hmac_sha512(
                self.chain_code.as_slice(),
                &[&[0], self.key.as_slice(), &index_bytes],
            )?
        };
        let (il, chain_code) = split_halves(&output);
        let key = ckd_from_il(&self.key, &il)?;
        Ok(Self {
            key,
            chain_code,
            depth,
            child_number: index,
        })
    }

    /// Derives every component of `path` from this node.
    pub(crate) fn derive_path(
        &self,
        ctx: &Secp256k1<All>,
        path: &Bip32Path,
    ) -> Result<Self, KeyError> {
        let mut node = Self {
            key: Zeroizing::new(*self.key),
            chain_code: Zeroizing::new(*self.chain_code),
            depth: self.depth,
            child_number: self.child_number,
        };
        for index in path.components() {
            node = node.derive_child(ctx, *index)?;
        }
        Ok(node)
    }

    /// The private key; the caller must call `non_secure_erase` after use.
    pub(crate) fn secret_key(&self) -> Result<SecretKey, KeyError> {
        SecretKey::from_byte_array(*self.key).map_err(|_| KeyError::Internal)
    }

    /// The public key.
    pub(crate) fn public_key(&self, ctx: &Secp256k1<All>) -> Result<PublicKey, KeyError> {
        let mut secret = self.secret_key()?;
        let public = PublicKey::from_secret_key(ctx, &secret);
        secret.non_secure_erase();
        Ok(public)
    }

    pub(crate) fn key_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    pub(crate) fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    pub(crate) const fn depth(&self) -> u8 {
        self.depth
    }

    pub(crate) const fn child_number(&self) -> u32 {
        self.child_number
    }
}

/// The EVM address of account `index` (`m/44'/60'/0'/0/i`) for a 64-byte BIP39 seed.
pub(crate) fn evm_address_from_seed(
    ctx: &Secp256k1<All>,
    seed: &[u8; 64],
    index: AccountIndex,
) -> Result<Address, KeyError> {
    let node = XPriv::from_seed(seed)?.derive_path(ctx, &evm_path(index))?;
    Ok(Address::from_public_key(&node.public_key(ctx)?))
}

/// The private key at `path` for a 64-byte BIP39 seed; the caller erases it.
pub(crate) fn secret_key_from_seed(
    ctx: &Secp256k1<All>,
    seed: &[u8; 64],
    path: &Bip32Path,
) -> Result<SecretKey, KeyError> {
    XPriv::from_seed(seed)?.derive_path(ctx, path)?.secret_key()
}

/// Address preview for import (spec/02 §10.3, spec/04 §2.4 `KeyJob::PreviewImport`): parses the
/// phrase and derives account `index` without a vault. Nothing is stored; intermediates are wiped.
///
/// # Errors
///
/// The [`Mnemonic::parse`] errors, [`KeyError::PassphraseEmpty`] for `Some` empty passphrase,
/// [`KeyError::RandomnessUnavailable`] for the context seed, or a derivation error.
pub fn preview_evm_address(
    phrase: &str,
    passphrase: Option<&Bip39Passphrase>,
    index: AccountIndex,
) -> Result<Address, KeyError> {
    let mnemonic = Mnemonic::parse(phrase)?;
    let empty = Bip39Passphrase::empty();
    let passphrase = match passphrase {
        Some(value) if value.is_empty() => return Err(KeyError::PassphraseEmpty),
        Some(value) => value,
        None => &empty,
    };
    let seed = mnemonic.to_seed(passphrase);
    let ctx = secp_context(&mut OsRandom)?;
    evm_address_from_seed(&ctx, &seed, index)
}

#[cfg(test)]
mod tests;
