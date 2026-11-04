//! Bitcoin account kinds (spec/08 §3): the four address types an account can have, the public
//! key material of an account (an HD account node `m/{44|49|84|86}'/{coin}'/{account}'`, or a
//! single imported key), our output script of `(chain, index)`, and the key reference signing
//! asks the vault for.
//!
//! | `ScriptType` (stable `u8`) | path | our output | spending input |
//! |---|---|---|---|
//! | `P2pkh` = 1 | BIP44 `m/44'/c'/a'` | `76 a9 14 HASH160(K) 88 ac` | scriptSig `<sig> <K>` (legacy sighash) |
//! | `P2shP2wpkh` = 2 | BIP49 `m/49'/c'/a'` | `a9 14 HASH160(00 14 HASH160(K)) 87` | scriptSig `16 00 14 <h>`, witness `[sig, K]` (BIP143) |
//! | `P2wpkh` = 3 | BIP84 `m/84'/c'/a'` | `00 14 HASH160(K)` | witness `[sig, K]` (BIP143) |
//! | `P2tr` = 4 | BIP86 `m/86'/c'/a'` | `51 20 Q` with `Q = P + TaggedHash("TapTweak", P)·G` | witness `[schnorr64]` (BIP341 key path, `SIGHASH_DEFAULT`) |
//!
//! The `u8` values are stored in meta, journal records and (by the key-import work) vault records
//! of imported keys: never renumber them.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use secp256k1::{All, PublicKey, Secp256k1, Verification, XOnlyPublicKey};

use super::address::{BtcAddress, ScriptKind, hash160, script_pubkey};
use super::network::BtcNetwork;
use super::script::{
    P2PKH_SPK_LEN, P2SH_SPK_LEN, P2TR_SPK_LEN, P2WPKH_SPK_LEN, p2sh_p2wpkh_redeem_script,
};
use super::taproot::output_key;
use crate::bip32::path::{BtcChain, BtcCoin, BtcPurpose};
use crate::bip32::{AccountXpub, HARDENED, derive_public_child_with};
use crate::entropy::{OsRandom, secp_context};
use crate::error::KeyError;

/// Largest HD account number a new BTC account may get (`m/{p}'/{c}'/0'` … `/99'`).
pub const BTC_MAX_HD_ACCOUNT: u32 = 99;

/// The address type of an account (stable codes, see the module table).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ScriptType {
    /// Legacy P2PKH (`1…` / `m…`·`n…`), BIP44.
    P2pkh = 1,
    /// Nested segwit P2SH-P2WPKH (`3…` / `2…`), BIP49.
    P2shP2wpkh = 2,
    /// Native segwit P2WPKH (`bc1q…` / `tb1q…`), BIP84 — the default.
    P2wpkh = 3,
    /// Taproot key path P2TR (`bc1p…` / `tb1p…`), BIP86.
    P2tr = 4,
}

impl ScriptType {
    /// The add-account choices in display order (recommended first).
    pub const CHOICES: [Self; 4] = [Self::P2wpkh, Self::P2tr, Self::P2shP2wpkh, Self::P2pkh];

    /// The stable code (meta, journal, vault).
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Inverse of [`ScriptType::code`].
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::P2pkh),
            2 => Some(Self::P2shP2wpkh),
            3 => Some(Self::P2wpkh),
            4 => Some(Self::P2tr),
            _ => None,
        }
    }

    /// The BIP43 purpose of its HD accounts.
    #[must_use]
    pub const fn purpose(self) -> BtcPurpose {
        match self {
            Self::P2pkh => BtcPurpose::Bip44,
            Self::P2shP2wpkh => BtcPurpose::Bip49,
            Self::P2wpkh => BtcPurpose::Bip84,
            Self::P2tr => BtcPurpose::Bip86,
        }
    }

    /// Plain Korean name (account rows, receive screen).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::P2pkh => "레거시",
            Self::P2shP2wpkh => "호환 세그윗",
            Self::P2wpkh => "네이티브 세그윗",
            Self::P2tr => "탭루트",
        }
    }

    /// The address prefix on `net` (`bc1q…`, `bc1p…`, `3…`, `1…`; testnet4 `tb1q…`, `tb1p…`,
    /// `2…`, `m·n…`).
    #[must_use]
    pub const fn prefix(self, net: BtcNetwork) -> &'static str {
        match (self, net) {
            (Self::P2pkh, BtcNetwork::Mainnet) => "1…",
            (Self::P2pkh, BtcNetwork::Testnet4) => "m·n…",
            (Self::P2shP2wpkh, BtcNetwork::Mainnet) => "3…",
            (Self::P2shP2wpkh, BtcNetwork::Testnet4) => "2…",
            (Self::P2wpkh, BtcNetwork::Mainnet) => "bc1q…",
            (Self::P2wpkh, BtcNetwork::Testnet4) => "tb1q…",
            (Self::P2tr, BtcNetwork::Mainnet) => "bc1p…",
            (Self::P2tr, BtcNetwork::Testnet4) => "tb1p…",
        }
    }

    /// The add-account choice text: `네이티브 세그윗 (bc1q…, 권장)`, `탭루트 (bc1p…)`,
    /// `호환 세그윗 (3…)`, `레거시 (1…)` (testnet4 prefixes `tb1q`/`tb1p`/`2`/`m·n`).
    #[must_use]
    pub fn label(self, net: BtcNetwork) -> String {
        match self {
            Self::P2wpkh => format!("{} ({}, 권장)", self.name(), self.prefix(net)),
            _ => format!("{} ({})", self.name(), self.prefix(net)),
        }
    }

    /// Technical name (approval details).
    #[must_use]
    pub const fn technical(self) -> &'static str {
        match self {
            Self::P2pkh => "P2PKH",
            Self::P2shP2wpkh => "P2SH-P2WPKH",
            Self::P2wpkh => "P2WPKH",
            Self::P2tr => "P2TR",
        }
    }

    /// The meta JSON name.
    #[must_use]
    pub const fn json_name(self) -> &'static str {
        match self {
            Self::P2pkh => "p2pkh",
            Self::P2shP2wpkh => "p2sh-p2wpkh",
            Self::P2wpkh => "p2wpkh",
            Self::P2tr => "p2tr",
        }
    }

    /// Inverse of [`ScriptType::json_name`] (exact).
    #[must_use]
    pub fn parse_json_name(text: &str) -> Option<Self> {
        Self::CHOICES
            .into_iter()
            .find(|kind| kind.json_name() == text)
    }

    /// Spending needs witness data (all but P2PKH).
    #[must_use]
    pub const fn is_segwit(self) -> bool {
        !matches!(self, Self::P2pkh)
    }

    /// scriptPubKey length of our outputs of this type (change size, spec/08 §7.2).
    #[must_use]
    pub const fn spk_len(self) -> usize {
        match self {
            Self::P2pkh => P2PKH_SPK_LEN,
            Self::P2shP2wpkh => P2SH_SPK_LEN,
            Self::P2wpkh => P2WPKH_SPK_LEN,
            Self::P2tr => P2TR_SPK_LEN,
        }
    }

    /// Pre-signing weight of one input spending our output of this type (spec/08 §7.2), an upper
    /// bound of the signed weight (low-R ECDSA `DER ‖ 0x01` ≤ 71 bytes, Schnorr exactly 64):
    ///
    /// - P2WPKH `41·4 + 107` = 271 (witness: count 1, 1 + 71, 1 + 33);
    /// - P2SH-P2WPKH `(41 + 23)·4 + 107` = 363 (scriptSig `16 00 14 <h>`);
    /// - P2TR `41·4 + 66` = 230 (witness: count 1, 1 + 64);
    /// - P2PKH `(41 + 106)·4` = 588 compressed (scriptSig `1 + 71 + 1 + 33`), `(41 + 138)·4` = 716
    ///   uncompressed (`1 + 71 + 1 + 65`).
    #[must_use]
    pub const fn input_weight(self, compressed: bool) -> u64 {
        match self {
            Self::P2wpkh => 271,
            Self::P2shP2wpkh => 363,
            Self::P2tr => 230,
            Self::P2pkh => {
                if compressed {
                    588
                } else {
                    716
                }
            }
        }
    }
}

impl fmt::Display for ScriptType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// Why an account key description was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccountKeyError {
    /// Not a 33-byte `02`/`03` or 65-byte `04` point on the curve.
    PublicKey,
    /// An uncompressed key is only usable as P2PKH (segwit and Taproot need compressed keys).
    UncompressedNotP2pkh,
    /// The HD account number is hardened (≥ 2^31).
    Account,
}

impl fmt::Display for AccountKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PublicKey => "공개키 형식이 올바르지 않습니다",
            Self::UncompressedNotP2pkh => "비압축 키는 레거시(P2PKH) 주소로만 쓸 수 있습니다",
            Self::Account => "계정 번호가 범위를 벗어났습니다",
        })
    }
}

impl std::error::Error for AccountKeyError {}

/// A single key's public key: compressed (33 bytes, `02`/`03`) or uncompressed (65 bytes, `04`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum BtcPubKey {
    /// `02`/`03` ‖ x.
    Compressed([u8; 33]),
    /// `04` ‖ x ‖ y (legacy imported WIF keys without the compression flag).
    Uncompressed([u8; 65]),
}

impl fmt::Debug for BtcPubKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "BtcPubKey({})",
            crate::hex::encode(self.as_bytes())
        )
    }
}

impl BtcPubKey {
    /// Parses and validates a serialized point (33 bytes `02`/`03`, or 65 bytes `04`).
    ///
    /// # Errors
    ///
    /// [`AccountKeyError::PublicKey`].
    pub fn parse(bytes: &[u8]) -> Result<Self, AccountKeyError> {
        if let Ok(key) = <[u8; 33]>::try_from(bytes)
            && matches!(key.first(), Some(0x02 | 0x03))
            && PublicKey::from_byte_array_compressed(key).is_ok()
        {
            return Ok(Self::Compressed(key));
        }
        if let Ok(key) = <[u8; 65]>::try_from(bytes)
            && key.first() == Some(&0x04)
            && PublicKey::from_byte_array_uncompressed(key).is_ok()
        {
            return Ok(Self::Uncompressed(key));
        }
        Err(AccountKeyError::PublicKey)
    }

    /// The serialized bytes (what P2PKH hashes and its scriptSig pushes).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Compressed(key) => key,
            Self::Uncompressed(key) => key,
        }
    }

    /// Compressed serialization.
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        matches!(self, Self::Compressed(_))
    }

    /// The compressed serialization of the same point (account identity of an uncompressed key).
    ///
    /// # Errors
    ///
    /// [`KeyError::DerivationFailed`] for an invalid point (never for a parsed key).
    pub fn compressed(&self) -> Result<[u8; 33], KeyError> {
        match self {
            Self::Compressed(key) => Ok(*key),
            Self::Uncompressed(key) => PublicKey::from_byte_array_uncompressed(*key)
                .map(|point| point.serialize())
                .map_err(|_| KeyError::DerivationFailed),
        }
    }

    /// The same point serialized as `secp256k1` computes it from a secret key with this key's
    /// compression.
    #[must_use]
    pub fn of_point(point: &PublicKey, compressed: bool) -> Self {
        if compressed {
            Self::Compressed(point.serialize())
        } else {
            Self::Uncompressed(point.serialize_uncompressed())
        }
    }
}

/// Our output kind for a compressed public key under `script_type` (see the module table).
///
/// # Errors
///
/// [`KeyError::DerivationFailed`] for an invalid key or tweak.
pub fn kind_for_compressed<C: Verification>(
    ctx: &Secp256k1<C>,
    script_type: ScriptType,
    pubkey: &[u8; 33],
) -> Result<ScriptKind, KeyError> {
    let hash = hash160(pubkey);
    Ok(match script_type {
        ScriptType::P2pkh => ScriptKind::P2pkh(hash),
        ScriptType::P2shP2wpkh => ScriptKind::P2sh(hash160(&p2sh_p2wpkh_redeem_script(&hash))),
        ScriptType::P2wpkh => ScriptKind::P2wpkh(hash),
        ScriptType::P2tr => {
            let mut x = [0_u8; 32];
            for (slot, byte) in x.iter_mut().zip(pubkey.iter().skip(1)) {
                *slot = *byte;
            }
            let internal =
                XOnlyPublicKey::from_byte_array(x).map_err(|_| KeyError::DerivationFailed)?;
            ScriptKind::P2tr(output_key(ctx, &internal, None)?.serialize())
        }
    })
}

/// Our output kind for a single key under `script_type` (an uncompressed key only as P2PKH).
///
/// # Errors
///
/// [`KeyError::DerivationFailed`] (also for an uncompressed key with a segwit type).
pub fn kind_for_key<C: Verification>(
    ctx: &Secp256k1<C>,
    script_type: ScriptType,
    pubkey: &BtcPubKey,
) -> Result<ScriptKind, KeyError> {
    match (pubkey, script_type) {
        (BtcPubKey::Compressed(key), _) => kind_for_compressed(ctx, script_type, key),
        (BtcPubKey::Uncompressed(key), ScriptType::P2pkh) => Ok(ScriptKind::P2pkh(hash160(key))),
        (BtcPubKey::Uncompressed(_), _) => Err(KeyError::DerivationFailed),
    }
}

/// The identity of an account (meta selection, journal records, activity rows).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BtcAccountId {
    /// HD account `m/{purpose}'/{coin}'/{account}'` of `script_type`.
    Hd {
        /// Address type.
        script_type: ScriptType,
        /// Account number.
        account: u32,
    },
    /// An imported single key (vault record id).
    Imported {
        /// Vault record id.
        id: [u8; 16],
    },
    /// The key of EVM account `evm_index` (`m/44'/60'/0'/0/i`) used for `script_type`: one fixed
    /// address (spec/08 §3.5 "EVM 계정과 같은 키").
    EvmShared {
        /// EVM account index (`AccountIndex`, 0–999).
        evm_index: u32,
        /// Address type.
        script_type: ScriptType,
    },
}

impl BtcAccountId {
    /// The BIP84 account 0 (meta `btc`, journal record version 1).
    pub const PRIMARY: Self = Self::Hd {
        script_type: ScriptType::P2wpkh,
        account: 0,
    };

    /// The `ActivityEntry.account` text: `""` for [`Self::PRIMARY`] (unchanged rows),
    /// `p2tr/0`-style for HD accounts, `imported/<32 hex>` for imported keys, `evm/p2tr/0`-style
    /// for an EVM account's key.
    #[must_use]
    pub fn activity_tag(&self) -> String {
        match self {
            _ if *self == Self::PRIMARY => String::new(),
            Self::Hd {
                script_type,
                account,
            } => format!("{}/{account}", script_type.json_name()),
            Self::Imported { id } => format!("imported/{}", crate::hex::encode(id)),
            Self::EvmShared {
                evm_index,
                script_type,
            } => format!("evm/{}/{evm_index}", script_type.json_name()),
        }
    }
}

/// Where the signing key of one input comes from (spec/08 §11.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BtcKeySource {
    /// `m/{purpose}'/{coin}'/{account}'/{chain}/{index}` from the mnemonic.
    Derived {
        /// Address type (selects the purpose).
        script_type: ScriptType,
        /// Account number.
        account: u32,
        /// Receive or change chain.
        chain: BtcChain,
        /// Non-hardened index.
        index: u32,
    },
    /// An imported single key (vault tag 4, the key-import work).
    Imported {
        /// Vault record id.
        id: [u8; 16],
        /// Address type of the account.
        script_type: ScriptType,
        /// The account's public key is compressed (an uncompressed key is P2PKH only).
        compressed: bool,
    },
    /// The key of EVM account `evm_index`, `m/44'/60'/0'/0/i` from the mnemonic (vault
    /// `KeyRef::Evm(EvmKeySource::Derived)`, the same path on every BTC network).
    EvmShared {
        /// EVM account index.
        evm_index: u32,
        /// Address type of the account.
        script_type: ScriptType,
    },
}

impl BtcKeySource {
    /// The vault's account node of a derived key on `net` (`None` for imported keys and EVM
    /// keys).
    #[must_use]
    pub fn coin(&self, net: BtcNetwork) -> Option<BtcCoin> {
        match self {
            Self::Derived {
                script_type,
                account,
                ..
            } => net.account_node(script_type.purpose(), *account).ok(),
            Self::Imported { .. } | Self::EvmShared { .. } => None,
        }
    }

    /// Address type of the input.
    #[must_use]
    pub const fn script_type(&self) -> ScriptType {
        match self {
            Self::Derived { script_type, .. }
            | Self::Imported { script_type, .. }
            | Self::EvmShared { script_type, .. } => *script_type,
        }
    }
}

/// The public key material of one account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BtcAccountKey {
    /// An HD account: receive/change chains under the cached account node.
    Hd {
        /// Address type.
        script_type: ScriptType,
        /// Account number (`< 2^31`).
        account: u32,
        /// `m/{purpose}'/{coin}'/{account}'` (public).
        xpub: AccountXpub,
        /// Fixed-address mode (spec/08 §3.5 "고정 주소 모드", the default): the receive screen
        /// shows only `(Receive, 0)` and change goes back to it, like UniSat/Xverse. Discovery
        /// and the watch set stay HD, so outputs on other addresses of the account are still
        /// seen and spent. `false`: a new receive address each time and the change chain (HD).
        single_address: bool,
    },
    /// One imported key: one address, change back to it, no gap scan.
    Single {
        /// Vault record id.
        id: [u8; 16],
        /// Address type.
        script_type: ScriptType,
        /// Public key (uncompressed only with `P2pkh`).
        pubkey: BtcPubKey,
    },
    /// The key of EVM account `evm_index` (`m/44'/60'/0'/0/i`) for `script_type`: one address,
    /// change back to it, no gap scan (like [`Self::Single`], but derived from the mnemonic and
    /// signed through the vault's EVM key).
    EvmShared {
        /// EVM account index (0–999).
        evm_index: u32,
        /// Address type.
        script_type: ScriptType,
        /// Compressed public key of `m/44'/60'/0'/0/{evm_index}`.
        pubkey: [u8; 33],
    },
}

impl BtcAccountKey {
    /// The BIP84 account 0 node (meta `btc`), in fixed-address mode.
    #[must_use]
    pub const fn primary(xpub: AccountXpub) -> Self {
        Self::Hd {
            script_type: ScriptType::P2wpkh,
            account: 0,
            xpub,
            single_address: true,
        }
    }

    /// An HD account node, in fixed-address mode (the default; see
    /// [`BtcAccountKey::with_single_address`]).
    ///
    /// # Errors
    ///
    /// [`AccountKeyError::Account`] for a hardened account, [`AccountKeyError::PublicKey`] for an
    /// invalid node key.
    pub fn hd(
        script_type: ScriptType,
        account: u32,
        xpub: AccountXpub,
    ) -> Result<Self, AccountKeyError> {
        if account >= HARDENED {
            return Err(AccountKeyError::Account);
        }
        if !matches!(xpub.pubkey.first(), Some(0x02 | 0x03))
            || PublicKey::from_byte_array_compressed(xpub.pubkey).is_err()
        {
            return Err(AccountKeyError::PublicKey);
        }
        Ok(Self::Hd {
            script_type,
            account,
            xpub,
            single_address: true,
        })
    }

    /// An imported single key.
    ///
    /// # Errors
    ///
    /// [`AccountKeyError::UncompressedNotP2pkh`] for an uncompressed key with a segwit type.
    pub const fn single(
        id: [u8; 16],
        script_type: ScriptType,
        pubkey: BtcPubKey,
    ) -> Result<Self, AccountKeyError> {
        if !pubkey.is_compressed() && !matches!(script_type, ScriptType::P2pkh) {
            return Err(AccountKeyError::UncompressedNotP2pkh);
        }
        Ok(Self::Single {
            id,
            script_type,
            pubkey,
        })
    }

    /// The account on the key of EVM account `evm_index` (`m/44'/60'/0'/0/i`, public key from
    /// `Vault::evm_public_key`).
    ///
    /// # Errors
    ///
    /// [`AccountKeyError::Account`] above EVM account 999, [`AccountKeyError::PublicKey`] for an
    /// invalid compressed point.
    pub fn evm_shared(
        evm_index: u32,
        script_type: ScriptType,
        pubkey: [u8; 33],
    ) -> Result<Self, AccountKeyError> {
        if crate::bip32::path::AccountIndex::new(evm_index).is_err() {
            return Err(AccountKeyError::Account);
        }
        if !matches!(pubkey.first(), Some(0x02 | 0x03))
            || PublicKey::from_byte_array_compressed(pubkey).is_err()
        {
            return Err(AccountKeyError::PublicKey);
        }
        Ok(Self::EvmShared {
            evm_index,
            script_type,
            pubkey,
        })
    }

    /// The same HD account in fixed-address (`true`) or HD (`false`) mode; other keys are
    /// always one address and stay unchanged.
    #[must_use]
    pub const fn with_single_address(self, on: bool) -> Self {
        match self {
            Self::Hd {
                script_type,
                account,
                xpub,
                ..
            } => Self::Hd {
                script_type,
                account,
                xpub,
                single_address: on,
            },
            other => other,
        }
    }

    /// Address type.
    #[must_use]
    pub const fn script_type(&self) -> ScriptType {
        match self {
            Self::Hd { script_type, .. }
            | Self::Single { script_type, .. }
            | Self::EvmShared { script_type, .. } => *script_type,
        }
    }

    /// One key with one address and no chains (an imported key or an EVM account's key): no gap
    /// scan, no "새 주소", change back to the same address.
    #[must_use]
    pub const fn is_single(&self) -> bool {
        matches!(self, Self::Single { .. } | Self::EvmShared { .. })
    }

    /// An imported key (vault tag 4 record; listed, revealed and removed with the record).
    #[must_use]
    pub const fn is_imported(&self) -> bool {
        matches!(self, Self::Single { .. })
    }

    /// The account uses the key of an EVM account.
    #[must_use]
    pub const fn is_evm_shared(&self) -> bool {
        matches!(self, Self::EvmShared { .. })
    }

    /// An HD account (receive and change chains, discovery).
    #[must_use]
    pub const fn is_hd(&self) -> bool {
        matches!(self, Self::Hd { .. })
    }

    /// Receiving and change always use `(Receive, 0)`: every one-key account, and an HD account
    /// in fixed-address mode (spec/08 §3.5).
    #[must_use]
    pub const fn fixed_address(&self) -> bool {
        match self {
            Self::Hd { single_address, .. } => *single_address,
            Self::Single { .. } | Self::EvmShared { .. } => true,
        }
    }

    /// The account identity.
    #[must_use]
    pub const fn id(&self) -> BtcAccountId {
        match self {
            Self::Hd {
                script_type,
                account,
                ..
            } => BtcAccountId::Hd {
                script_type: *script_type,
                account: *account,
            },
            Self::Single { id, .. } => BtcAccountId::Imported { id: *id },
            Self::EvmShared {
                evm_index,
                script_type,
                ..
            } => BtcAccountId::EvmShared {
                evm_index: *evm_index,
                script_type: *script_type,
            },
        }
    }

    /// The approval `AccountRef::Bitcoin` key: the HD node's public key, or the single key's
    /// compressed public key (the payload carries the address type and source as well).
    #[must_use]
    pub fn identity(&self) -> [u8; 33] {
        match self {
            Self::Hd { xpub, .. } => xpub.pubkey,
            Self::Single { pubkey, .. } => pubkey.compressed().unwrap_or([0; 33]),
            Self::EvmShared { pubkey, .. } => *pubkey,
        }
    }

    /// The cached HD node (`None` for a single key).
    #[must_use]
    pub const fn xpub(&self) -> Option<&AccountXpub> {
        match self {
            Self::Hd { xpub, .. } => Some(xpub),
            Self::Single { .. } | Self::EvmShared { .. } => None,
        }
    }

    /// Pre-signing weight of one of this account's inputs.
    #[must_use]
    pub const fn input_weight(&self) -> u64 {
        match self {
            Self::Hd { script_type, .. } | Self::EvmShared { script_type, .. } => {
                script_type.input_weight(true)
            }
            Self::Single {
                script_type,
                pubkey,
                ..
            } => script_type.input_weight(pubkey.is_compressed()),
        }
    }

    /// The key of input `(chain, index)`.
    #[must_use]
    pub const fn key_source(&self, chain: BtcChain, index: u32) -> BtcKeySource {
        match self {
            Self::Hd {
                script_type,
                account,
                ..
            } => BtcKeySource::Derived {
                script_type: *script_type,
                account: *account,
                chain,
                index,
            },
            Self::Single {
                id,
                script_type,
                pubkey,
            } => BtcKeySource::Imported {
                id: *id,
                script_type: *script_type,
                compressed: pubkey.is_compressed(),
            },
            Self::EvmShared {
                evm_index,
                script_type,
                ..
            } => BtcKeySource::EvmShared {
                evm_index: *evm_index,
                script_type: *script_type,
            },
        }
    }

    /// The `(chain, index)` of change output `index`: the change chain of an HD account in HD
    /// mode; `(Receive, 0)` — the account's one receive address — for a fixed-address account
    /// ([`BtcAccountKey::fixed_address`]).
    #[must_use]
    pub const fn change_path(&self, index: u32) -> (BtcChain, u32) {
        if self.fixed_address() {
            (BtcChain::Receive, 0)
        } else {
            (BtcChain::Change, index)
        }
    }

    /// Where a recorded change output `index` may be, preferred first: [`Self::change_path`],
    /// then for an HD account the other mode's path (a record written before the mode was
    /// switched). Callers match the output script to pick one.
    #[must_use]
    pub fn change_candidates(&self, index: u32) -> Vec<(BtcChain, u32)> {
        let first = self.change_path(index);
        let mut out = vec![first];
        if self.is_hd() {
            let other = if self.fixed_address() {
                (BtcChain::Change, index)
            } else {
                (BtcChain::Receive, 0)
            };
            if other != first {
                out.push(other);
            }
        }
        out
    }

    /// The path text of `(chain, index)` on `net`: `m/86'/0'/0'/0/5`, `m/44'/60'/0'/0/3` for an
    /// EVM account's key, or `가져온 키` for an imported key.
    #[must_use]
    pub fn path_text(&self, net: BtcNetwork, chain: BtcChain, index: u32) -> String {
        match self {
            Self::Hd {
                script_type,
                account,
                ..
            } => format!(
                "m/{}'/{}'/{account}'/{}/{index}",
                script_type.purpose().number(),
                net.coin_number(),
                chain.index()
            ),
            Self::Single { .. } => "가져온 키".to_owned(),
            Self::EvmShared { evm_index, .. } => format!("m/44'/60'/0'/0/{evm_index}"),
        }
    }

    /// The account node text: `m/86'/0'/0'`, `m/44'/60'/0'/0/3` for an EVM account's key, or
    /// `가져온 키` for an imported key.
    #[must_use]
    pub fn node_text(&self, net: BtcNetwork) -> String {
        match self {
            Self::Hd {
                script_type,
                account,
                ..
            } => format!(
                "m/{}'/{}'/{account}'",
                script_type.purpose().number(),
                net.coin_number()
            ),
            Self::Single { .. } => "가져온 키".to_owned(),
            Self::EvmShared { evm_index, .. } => format!("m/44'/60'/0'/0/{evm_index}"),
        }
    }

    /// The display name: `네이티브 세그윗 계정 0`, `탭루트 계정 2`, `가져온 키 · 레거시`,
    /// `EVM 계정 3 키 · 탭루트`.
    #[must_use]
    pub fn display_name(&self) -> String {
        match self {
            Self::Hd {
                script_type,
                account,
                ..
            } => format!("{} 계정 {account}", script_type.name()),
            Self::Single { script_type, .. } => format!("가져온 키 · {}", script_type.name()),
            Self::EvmShared {
                evm_index,
                script_type,
                ..
            } => format!("EVM 계정 {evm_index} 키 · {}", script_type.name()),
        }
    }

    /// A deriver for many `(chain, index)` with one context.
    ///
    /// # Errors
    ///
    /// [`KeyError`] (randomness for the context, chain node derivation).
    pub fn deriver(&self) -> Result<AccountDeriver, KeyError> {
        AccountDeriver::new(*self)
    }

    /// Our output kind of `(chain, index)`.
    ///
    /// # Errors
    ///
    /// [`KeyError::InvalidPath`] for a hardened index (or anything but `(Receive, 0)` of a single
    /// key), [`KeyError::DerivationFailed`], [`KeyError::RandomnessUnavailable`].
    pub fn kind(&self, chain: BtcChain, index: u32) -> Result<ScriptKind, KeyError> {
        self.deriver()?.kind(chain, index)
    }

    /// Our scriptPubKey of `(chain, index)`.
    ///
    /// # Errors
    ///
    /// As [`BtcAccountKey::kind`].
    pub fn script(&self, chain: BtcChain, index: u32) -> Result<Vec<u8>, KeyError> {
        Ok(script_pubkey(&self.kind(chain, index)?))
    }

    /// Our address of `(chain, index)` on `net`.
    ///
    /// # Errors
    ///
    /// As [`BtcAccountKey::kind`].
    pub fn address(
        &self,
        net: BtcNetwork,
        chain: BtcChain,
        index: u32,
    ) -> Result<BtcAddress, KeyError> {
        Ok(BtcAddress::ours(net, self.kind(chain, index)?))
    }
}

/// Batch derivation of an account's outputs and public keys with one context (watch set,
/// own-recipient search, signing and post-sign checks).
#[derive(Debug)]
pub struct AccountDeriver {
    key: BtcAccountKey,
    ctx: Secp256k1<All>,
    chains: Option<(AccountXpub, AccountXpub)>,
}

impl AccountDeriver {
    fn new(key: BtcAccountKey) -> Result<Self, KeyError> {
        let ctx = secp_context(&mut OsRandom)?;
        let chains = match &key {
            BtcAccountKey::Hd { xpub, .. } => Some((
                derive_public_child_with(&ctx, xpub, BtcChain::Receive.index())?,
                derive_public_child_with(&ctx, xpub, BtcChain::Change.index())?,
            )),
            BtcAccountKey::Single { .. } | BtcAccountKey::EvmShared { .. } => None,
        };
        Ok(Self { key, ctx, chains })
    }

    /// The context (for signature checks next to the derivation).
    #[must_use]
    pub const fn ctx(&self) -> &Secp256k1<All> {
        &self.ctx
    }

    /// The public key of `(chain, index)`: the derived compressed key, or the single key for
    /// `(Receive, 0)`.
    ///
    /// # Errors
    ///
    /// [`KeyError::InvalidPath`], [`KeyError::DerivationFailed`].
    pub fn pubkey(&self, chain: BtcChain, index: u32) -> Result<BtcPubKey, KeyError> {
        if index & HARDENED != 0 {
            return Err(KeyError::InvalidPath);
        }
        match (&self.key, &self.chains) {
            (BtcAccountKey::Hd { .. }, Some((receive, change))) => {
                let parent = match chain {
                    BtcChain::Receive => receive,
                    BtcChain::Change => change,
                };
                Ok(BtcPubKey::Compressed(
                    derive_public_child_with(&self.ctx, parent, index)?.pubkey,
                ))
            }
            (BtcAccountKey::Single { pubkey, .. }, _) => {
                if chain == BtcChain::Receive && index == 0 {
                    Ok(*pubkey)
                } else {
                    Err(KeyError::InvalidPath)
                }
            }
            (BtcAccountKey::EvmShared { pubkey, .. }, _) => {
                if chain == BtcChain::Receive && index == 0 {
                    Ok(BtcPubKey::Compressed(*pubkey))
                } else {
                    Err(KeyError::InvalidPath)
                }
            }
            (BtcAccountKey::Hd { .. }, None) => Err(KeyError::DerivationFailed),
        }
    }

    /// Our output kind of `(chain, index)`.
    ///
    /// # Errors
    ///
    /// As [`AccountDeriver::pubkey`].
    pub fn kind(&self, chain: BtcChain, index: u32) -> Result<ScriptKind, KeyError> {
        kind_for_key(
            &self.ctx,
            self.key.script_type(),
            &self.pubkey(chain, index)?,
        )
    }

    /// Our scriptPubKey of `(chain, index)`.
    ///
    /// # Errors
    ///
    /// As [`AccountDeriver::pubkey`].
    pub fn script(&self, chain: BtcChain, index: u32) -> Result<Vec<u8>, KeyError> {
        Ok(script_pubkey(&self.kind(chain, index)?))
    }

    /// The scriptSig of an input spending `(chain, index)` before signing: the redeem-script push
    /// `16 00 14 <h>` for P2SH-P2WPKH (fixed, so the txid is known before signing), empty
    /// otherwise (P2PKH gets `<sig> <K>` when signed).
    ///
    /// # Errors
    ///
    /// As [`AccountDeriver::pubkey`].
    pub fn unsigned_script_sig(&self, chain: BtcChain, index: u32) -> Result<Vec<u8>, KeyError> {
        if self.key.script_type() != ScriptType::P2shP2wpkh {
            return Ok(Vec::new());
        }
        let key = self.pubkey(chain, index)?;
        Ok(super::script::p2sh_p2wpkh_script_sig(&hash160(key.as_bytes())).to_vec())
    }
}
