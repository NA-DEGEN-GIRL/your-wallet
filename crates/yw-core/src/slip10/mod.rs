//! SLIP-0010 Ed25519 derivation (hardened only) and the Solana key sources (spec/02 §3.5,
//! spec/07 §3, M7).
//!
//! The derivation result is an RFC 8032 secret seed. It is only ever handed to
//! `ed25519_dalek::SigningKey::from_bytes` inside `Vault::with_ed25519_seed` /
//! `Vault::sol_public_keys`; no public API returns it.

use core::fmt;
use core::str::FromStr;

use zeroize::Zeroizing;

use crate::bip32::path::AccountIndex;
use crate::bip32::{HARDENED, MAX_PATH_DEPTH, hmac_sha512, split_halves};
use crate::error::KeyError;

/// HMAC key of the SLIP-0010 Ed25519 master node.
pub const SLIP10_ED25519_KEY: &[u8] = b"ed25519 seed";
/// `44'` (BIP44 purpose, hardened).
const PURPOSE_44H: u32 = 0x8000_002C;
/// `501'` (SLIP-0044 Solana coin type, hardened).
const COIN_501H: u32 = 0x8000_01F5;

/// A path whose components are all hardened, depth 1..=10 (spec/02 §3.5). Never accepts a
/// non-hardened component and never promotes one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slip10Path {
    components: Vec<u32>,
}

impl Slip10Path {
    /// Builds a path from hardened components (bit 31 set on every one).
    ///
    /// # Errors
    ///
    /// [`KeyError::InvalidPath`] for an empty path, a depth above 10 or a non-hardened component.
    pub fn from_components(components: Vec<u32>) -> Result<Self, KeyError> {
        if components.is_empty()
            || components.len() > MAX_PATH_DEPTH
            || components.iter().any(|component| component & HARDENED == 0)
        {
            return Err(KeyError::InvalidPath);
        }
        Ok(Self { components })
    }

    /// Child numbers (all with bit 31 set).
    #[must_use]
    pub fn components(&self) -> &[u32] {
        &self.components
    }
}

impl FromStr for Slip10Path {
    type Err = KeyError;

    /// Grammar: `"m/" comp' ("/" comp')*`, `comp = "0" | [1-9][0-9]*`, value < 2^31, every
    /// component with `'`, depth 1..=10.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let rest = input.strip_prefix("m/").ok_or(KeyError::InvalidPath)?;
        let components = rest
            .split('/')
            .map(|component| {
                let digits = component.strip_suffix('\'').ok_or(KeyError::InvalidPath)?;
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
                Ok(value | HARDENED)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_components(components)
    }
}

impl fmt::Display for Slip10Path {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("m")?;
        for component in &self.components {
            write!(formatter, "/{}'", component & !HARDENED)?;
        }
        Ok(())
    }
}

/// A SLIP-0010 node: key and chain code (secret, wiped on drop).
pub(crate) struct Node {
    pub(crate) key: Zeroizing<[u8; 32]>,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "only the SLIP-0010 vector tests read the chain code"
        )
    )]
    pub(crate) chain_code: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for Node {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Node([REDACTED])")
    }
}

/// `I = HMAC-SHA512("ed25519 seed", seed)`, `k = IL`, `c = IR`, then for every (hardened)
/// component `I = HMAC-SHA512(c, 0x00 ‖ k ‖ ser32(i))`. Any seed length (test vectors use 16
/// and 64 bytes); a non-hardened component is `InvalidPath`.
pub(crate) fn derive_node(seed: &[u8], components: &[u32]) -> Result<Node, KeyError> {
    let output = hmac_sha512(SLIP10_ED25519_KEY, &[seed])?;
    let (mut key, mut chain_code) = split_halves(&output);
    for component in components {
        if component & HARDENED == 0 {
            return Err(KeyError::InvalidPath);
        }
        let output = hmac_sha512(
            chain_code.as_slice(),
            &[&[0], key.as_slice(), &component.to_be_bytes()],
        )?;
        let (child_key, child_chain) = split_halves(&output);
        key = child_key;
        chain_code = child_chain;
    }
    Ok(Node { key, chain_code })
}

/// The 32-byte Ed25519 secret seed at `path` for a 64-byte BIP39 seed (spec/02 §3.5).
pub(crate) fn slip10_ed25519(
    seed: &[u8; 64],
    path: &Slip10Path,
) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    Ok(derive_node(seed, path.components())?.key)
}

/// `m/44'/501'/i'/0'` (`SolKeySource::Standard`, D25, D29).
#[must_use]
pub fn sol_path(index: AccountIndex) -> Slip10Path {
    Slip10Path {
        components: vec![PURPOSE_44H, COIN_501H, index.get() | HARDENED, HARDENED],
    }
}

/// Where a Solana Ed25519 seed comes from (spec/02 §3.5, tags spec/07 §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SolKeySource {
    /// `m/44'/501'/i'/0'` (Phantom, Solflare, Backpack; the only source of new accounts). Tag 1.
    Standard(AccountIndex),
    /// `m/44'/501'/i'` (Ledger Live, Sollet "bip44"). Tag 2.
    Bip44Account(AccountIndex),
    /// `m/44'/501'` (solana-keygen `prompt://` default). Tag 3.
    Bip44Root,
    /// No derivation: BIP39 seed `[0..32]` (`solana-keygen new`). Tag 4.
    RawSeed,
    /// Sollet legacy (tag 5). Not implemented (spec/07 §3.2: no confirmed vector); every use is
    /// `KeyError::InvalidPath`.
    SolletLegacy {
        /// Wallet index.
        wallet: u32,
        /// Account index.
        account: u32,
    },
    /// An imported private key (vault `tag 3`, spec/02 §8.4), outside the mnemonic. The key is
    /// found by its public key (`intent.core.from`), so the source carries no parameters. Tag 6.
    Imported,
    /// Solana account `i` (`m/44'/501'/i'/0'`) whose Ed25519 key lives in a `YubiKey` PIV slot
    /// (spec/10 §3.1, vault tag 5). The PC holds only the public key: the vault never lends a
    /// seed for it (`VaultError::RecordNotFound`) and the signature comes from the card
    /// (`sol::sign::sign_transfer_card`, `sol::msgsign::sign_message_card`). Tag 7.
    Hardware(AccountIndex),
    /// Standard-path account `m/44'/501'/i'/0'` of an added mnemonic (the vault `Bip39` record
    /// `id`, spec/02 §8.6). Tag 8; the journal and the approval transcripts carry the record id
    /// after `(a, b)` (spec/07 §13.2, §14.1). Signing needs that mnemonic's backup confirmed.
    Mnemonic(crate::vault::RecordId, AccountIndex),
}

impl SolKeySource {
    /// The source tag (spec/07 §3.2).
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Standard(_) => 1,
            Self::Bip44Account(_) => 2,
            Self::Bip44Root => 3,
            Self::RawSeed => 4,
            Self::SolletLegacy { .. } => 5,
            Self::Imported => 6,
            Self::Hardware(_) => 7,
            Self::Mnemonic(..) => 8,
        }
    }

    /// `(a, b)` of the intent transcript and journal header (spec/07 §13.2): the account index
    /// for tags 1, 2 and 7, `(wallet, account)` for tag 5, `(0, 0)` otherwise.
    #[must_use]
    pub const fn params(self) -> (u32, u32) {
        match self {
            Self::Standard(index)
            | Self::Bip44Account(index)
            | Self::Hardware(index)
            | Self::Mnemonic(_, index) => (index.get(), 0),
            Self::SolletLegacy { wallet, account } => (wallet, account),
            Self::Bip44Root | Self::RawSeed | Self::Imported => (0, 0),
        }
    }

    /// The added mnemonic of a tag-8 source (`None` for every other source: the primary
    /// mnemonic's, an imported key or a `YubiKey`).
    #[must_use]
    pub const fn mnemonic(self) -> Option<crate::vault::RecordId> {
        match self {
            Self::Mnemonic(id, _) => Some(id),
            _ => None,
        }
    }

    /// Rebuilds a tag-8 source (journal record version 2): a non-zero record id and an account
    /// index.
    ///
    /// # Errors
    ///
    /// [`KeyError::InvalidPath`] for a zero id or an index out of range.
    pub fn from_mnemonic_parts(id: [u8; 16], a: u32, b: u32) -> Result<Self, KeyError> {
        if id == [0; 16] || b != 0 {
            return Err(KeyError::InvalidPath);
        }
        let index = AccountIndex::new(a).map_err(|_| KeyError::InvalidPath)?;
        Ok(Self::Mnemonic(
            crate::vault::RecordId::from_bytes(id),
            index,
        ))
    }

    /// Rebuilds a source from its tag and parameters (journal header check; tag 8 needs the
    /// record id, [`SolKeySource::from_mnemonic_parts`]).
    ///
    /// # Errors
    ///
    /// [`KeyError::InvalidPath`] for an unknown tag or parameters outside the tag's rule.
    pub fn from_parts(tag: u8, a: u32, b: u32) -> Result<Self, KeyError> {
        let index = || AccountIndex::new(a).map_err(|_| KeyError::InvalidPath);
        match (tag, b) {
            (1, 0) => Ok(Self::Standard(index()?)),
            (2, 0) => Ok(Self::Bip44Account(index()?)),
            (3, 0) if a == 0 => Ok(Self::Bip44Root),
            (4, 0) if a == 0 => Ok(Self::RawSeed),
            (5, _) if a < HARDENED && b < HARDENED => Ok(Self::SolletLegacy {
                wallet: a,
                account: b,
            }),
            (6, 0) if a == 0 => Ok(Self::Imported),
            (7, 0) => Ok(Self::Hardware(index()?)),
            _ => Err(KeyError::InvalidPath),
        }
    }

    /// Whether this is the standard path (new accounts; tags 2–5 are recovery-scan only).
    #[must_use]
    pub const fn is_standard(self) -> bool {
        matches!(self, Self::Standard(_) | Self::Mnemonic(..))
    }

    /// Whether this is an imported key (tag 6).
    #[must_use]
    pub const fn is_imported(self) -> bool {
        matches!(self, Self::Imported)
    }

    /// Whether this is a `YubiKey` key (tag 7): signed on the card, never by the vault.
    #[must_use]
    pub const fn is_hardware(self) -> bool {
        matches!(self, Self::Hardware(_))
    }

    /// Whether the non-standard-path rule applies (spec/07 §3.3): a recovery-scan source
    /// (tags 2–5) may only "send max" to one of the wallet's own standard accounts. Standard,
    /// imported and `YubiKey` keys (the standard path on the card) send freely.
    #[must_use]
    pub const fn needs_move_rule(self) -> bool {
        !matches!(
            self,
            Self::Standard(_) | Self::Imported | Self::Hardware(_) | Self::Mnemonic(..)
        )
    }

    /// The path text shown to the user (`m/44'/501'/0'/0'`, `BIP39 seed[0..32]`, …).
    #[must_use]
    pub fn path_text(self) -> String {
        match self {
            Self::Standard(index) | Self::Mnemonic(_, index) => {
                format!("m/44'/501'/{}'/0'", index.get())
            }
            Self::Bip44Account(index) => format!("m/44'/501'/{}'", index.get()),
            Self::Bip44Root => "m/44'/501'".to_owned(),
            Self::RawSeed => "BIP39 seed[0..32] (파생 없음)".to_owned(),
            Self::SolletLegacy { wallet, account } => format!("m/501'/{wallet}'/0/{account}"),
            Self::Imported => "가져온 개인키 (복구 단어 밖)".to_owned(),
            Self::Hardware(index) if crate::yubikey::plan::is_unknown_index(index.get()) => {
                format!("{} (YubiKey PIV)", crate::yubikey::plan::T_UNKNOWN_PATH)
            }
            Self::Hardware(index) => format!("m/44'/501'/{}'/0' (YubiKey PIV)", index.get()),
        }
    }

    /// The 32-byte Ed25519 seed for a 64-byte BIP39 seed (spec/02 §3.5 table).
    pub(crate) fn ed25519_seed(self, seed: &[u8; 64]) -> Result<Zeroizing<[u8; 32]>, KeyError> {
        let path = match self {
            // The vault picks the seed of the source's mnemonic (spec/02 §8.6).
            Self::Standard(index) | Self::Mnemonic(_, index) => sol_path(index),
            Self::Bip44Account(index) => Slip10Path {
                components: vec![PURPOSE_44H, COIN_501H, index.get() | HARDENED],
            },
            Self::Bip44Root => Slip10Path {
                components: vec![PURPOSE_44H, COIN_501H],
            },
            Self::RawSeed => {
                let mut out = Zeroizing::new([0_u8; 32]);
                for (slot, byte) in out.iter_mut().zip(seed.iter()) {
                    *slot = *byte;
                }
                return Ok(out);
            }
            // A YubiKey key is on the card only; the vault refuses it before this point.
            Self::SolletLegacy { .. } | Self::Imported | Self::Hardware(_) => {
                return Err(KeyError::InvalidPath);
            }
        };
        slip10_ed25519(seed, &path)
    }
}

#[cfg(test)]
mod tests;
