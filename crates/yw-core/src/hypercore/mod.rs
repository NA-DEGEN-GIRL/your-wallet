//! Hyperliquid `HyperCore` (D34, spec/11): balances and user-signed transfers, no trading.
//!
//! The user-signed actions follow the official Python SDK `hyperliquid/utils/signing.py`
//! (`user_signed_payload`, `USD_SEND_SIGN_TYPES`, `SPOT_TRANSFER_SIGN_TYPES`,
//! `WITHDRAW_SIGN_TYPES`, `USD_CLASS_TRANSFER_SIGN_TYPES`, `SEND_ASSET_SIGN_TYPES`): EIP-712 domain
//! `{name: "HyperliquidSignTransaction", version: "1", chainId: signatureChainId,
//! verifyingContract: 0x0}`, primary type `HyperliquidTransaction:<Name>` and the fields in the
//! SDK order (every value a string except `time`/`nonce` `uint64` and `toPerp` `bool`). The
//! request bodies follow the API docs "Exchange endpoint" page. The encoding here is computed
//! directly (no JSON round trip) and the tests check it against the SDK's published signatures
//! and against [`crate::evm::eip712::validate_typed_data_v4`] of [`HcAction::typed_data_json`].
//!
//! No network, clock or randomness: yw-app supplies the nonce (wall-clock ms) and does the HTTP.
#![deny(clippy::indexing_slicing)]

pub mod display;
#[cfg(test)]
mod tests;

use core::fmt;

use sha3::{Digest, Keccak256};
use yw_json::{Number, Object, Value};

use crate::codec::transcript::Transcript;
use crate::evm::address::{Address, parse_address};
use crate::evm::amount::{U256, parse_units};
use crate::evm::eip712::TYPEHASH_DOMAIN_4;

/// Official mainnet API base URL (`/info`, `/exchange`).
pub const MAINNET_API: &str = "https://api.hyperliquid.xyz";
/// Official testnet API base URL.
pub const TESTNET_API: &str = "https://api.hyperliquid-testnet.xyz";
/// EIP-712 domain name of user-signed actions.
pub const DOMAIN_NAME: &str = "HyperliquidSignTransaction";
/// EIP-712 domain version.
pub const DOMAIN_VERSION: &str = "1";
/// Decimals of USDC amounts of `usdSend`, `withdraw3` and `usdClassTransfer` (Arbitrum USDC has
/// 6; the SDK's `float_to_usd_int` uses 6).
pub const USD_DECIMALS: u8 = 6;
/// The `withdraw3` fee in USDC, deducted on `HyperCore` (Hyperliquid UI and docs: "$1").
pub const WITHDRAW_FEE_USDC: &str = "1";
/// The HYPE system address (`HyperCore` ↔ `HyperEVM` transfers of the native token).
pub const HYPE_SYSTEM_ADDRESS: Address = Address::from_bytes([0x22; 20]);
/// Longest decimal amount text accepted on the wire.
const MAX_AMOUNT_TEXT: usize = 40;

fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

/// `HyperCore` network: the `hyperliquidChain` value and the API host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HcNetwork {
    /// `"Mainnet"`.
    Mainnet,
    /// `"Testnet"`.
    Testnet,
}

impl HcNetwork {
    /// The `hyperliquidChain` value.
    #[must_use]
    pub const fn chain_name(self) -> &'static str {
        match self {
            Self::Mainnet => "Mainnet",
            Self::Testnet => "Testnet",
        }
    }

    /// Settings / log word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
        }
    }

    /// Parses [`Self::as_str`].
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "mainnet" => Some(Self::Mainnet),
            "testnet" => Some(Self::Testnet),
            _ => None,
        }
    }

    /// Digest byte of [`crate::approval::ChainRef::HyperCore`].
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Mainnet => 1,
            Self::Testnet => 2,
        }
    }

    /// From [`Self::code`].
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Mainnet),
            2 => Some(Self::Testnet),
            _ => None,
        }
    }

    /// The `signatureChainId` this wallet signs with: Arbitrum One `0xa4b1` on mainnet (the API
    /// docs' examples) and Arbitrum Sepolia `0x66eee` on testnet (the SDK's value). Any chain id is
    /// accepted by Hyperliquid; `hyperliquidChain` is what prevents cross-network replay.
    #[must_use]
    pub const fn signature_chain_id(self) -> u64 {
        match self {
            Self::Mainnet => 42_161,
            Self::Testnet => 421_614,
        }
    }

    /// The `HyperEVM` chain id of this network (docs "HyperEVM": 999 mainnet, 998 testnet).
    #[must_use]
    pub const fn hyperevm_chain_id(self) -> u64 {
        match self {
            Self::Mainnet => 999,
            Self::Testnet => 998,
        }
    }

    /// The official API base URL.
    #[must_use]
    pub const fn default_api(self) -> &'static str {
        match self {
            Self::Mainnet => MAINNET_API,
            Self::Testnet => TESTNET_API,
        }
    }

    /// Display name.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Mainnet => "HyperCore 메인넷",
            Self::Testnet => "HyperCore 테스트넷",
        }
    }
}

/// Malformed input or response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HcError {
    /// An amount is not a positive canonical decimal with the allowed decimals.
    Amount,
    /// A token is not `NAME:0x<32 hex>`.
    Token,
    /// A dex name is neither `""` nor `"spot"`.
    Dex,
    /// The nonce is zero.
    Nonce,
    /// The response does not have the documented shape.
    Response,
}

impl fmt::Display for HcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Amount => "invalid HyperCore amount",
            Self::Token => "invalid HyperCore token",
            Self::Dex => "invalid HyperCore dex",
            Self::Nonce => "invalid HyperCore nonce",
            Self::Response => "unexpected HyperCore response",
        })
    }
}

impl std::error::Error for HcError {}

/// The system address of spot token `index`: `0x20`, zeros, then the index big-endian
/// (docs "`HyperCore` <> `HyperEVM` transfers"); HYPE uses [`HYPE_SYSTEM_ADDRESS`].
#[must_use]
pub fn system_address(index: u32) -> Address {
    let mut bytes = [0_u8; 20];
    if let Some(first) = bytes.first_mut() {
        *first = 0x20;
    }
    if let Some(tail) = bytes.get_mut(16..20) {
        tail.copy_from_slice(&index.to_be_bytes());
    }
    Address::from_bytes(bytes)
}

/// The token index of a system address (HYPE's `0x2222…` is not one), if `address` is one.
#[must_use]
pub fn system_address_index(address: &Address) -> Option<u32> {
    let bytes = address.as_bytes();
    let (head, tail) = bytes.split_at(16);
    let (first, zeros) = head.split_first()?;
    if *first != 0x20 || zeros.iter().any(|byte| *byte != 0) {
        return None;
    }
    let index: [u8; 4] = tail.try_into().ok()?;
    Some(u32::from_be_bytes(index))
}

/// Whether `text` is a wire amount: a positive decimal without sign, exponent, leading zeros
/// (except `0.`), trailing fraction zeros or a trailing dot, with at most `decimals` fraction
/// digits ("Issues with trailing zeroes on numbers", docs "Signing").
#[must_use]
pub fn is_wire_amount(text: &str, decimals: u8) -> bool {
    if text.is_empty() || text.len() > MAX_AMOUNT_TEXT {
        return false;
    }
    let (integer, fraction) = match text.split_once('.') {
        Some((integer, fraction)) => (integer, Some(fraction)),
        None => (text, None),
    };
    let integer_ok = integer == "0"
        || (!integer.is_empty()
            && !integer.starts_with('0')
            && integer.bytes().all(|byte| byte.is_ascii_digit()));
    let fraction_ok = fraction.is_none_or(|digits| {
        !digits.is_empty()
            && digits.len() <= usize::from(decimals)
            && !digits.ends_with('0')
            && digits.bytes().all(|byte| byte.is_ascii_digit())
    });
    integer_ok && fraction_ok && text.bytes().any(|byte| (b'1'..=b'9').contains(&byte))
}

/// The wire text of `units` smallest units with `decimals` (canonical, see [`is_wire_amount`]).
#[must_use]
pub fn wire_amount(units: &U256, decimals: u8) -> String {
    let digits = units.to_decimal_string();
    let places = usize::from(decimals);
    if places == 0 {
        return digits;
    }
    let padded = if digits.len() <= places {
        format!(
            "{}{digits}",
            "0".repeat(places.saturating_add(1).saturating_sub(digits.len()))
        )
    } else {
        digits
    };
    let split = padded.len().saturating_sub(places);
    let (integer, fraction) = padded.split_at(split);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        integer.to_owned()
    } else {
        format!("{integer}.{fraction}")
    }
}

/// Parses user input (`parse_units` rules) into the wire text and its smallest units.
///
/// # Errors
///
/// [`HcError::Amount`] for a malformed, zero or too precise amount.
pub fn parse_amount(text: &str, decimals: u8) -> Result<(U256, String), HcError> {
    let units = parse_units(text.trim(), decimals).map_err(|_| HcError::Amount)?;
    if units.is_zero() {
        return Err(HcError::Amount);
    }
    Ok((units, wire_amount(&units, decimals)))
}

/// Whether `text` is a spot token `NAME:0x<32 lowercase hex>` (docs: `"tokenName:tokenId"`).
#[must_use]
pub fn is_token_wire(text: &str) -> bool {
    let Some((name, id)) = text.rsplit_once(':') else {
        return false;
    };
    !name.is_empty()
        && name.len() <= 64
        && !name.chars().any(char::is_control)
        && id.len() == 34
        && id.strip_prefix("0x").is_some_and(|hex| {
            hex.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

/// One user-signed action (the fields besides `hyperliquidChain`/`signatureChainId`/nonce).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HcPayload {
    /// `usdSend`: perp USDC to another `HyperCore` address.
    UsdSend {
        /// Recipient.
        destination: Address,
        /// USDC amount (wire text, ≤ 6 decimals).
        amount: String,
    },
    /// `spotSend`: a spot token to another `HyperCore` address.
    SpotSend {
        /// Recipient.
        destination: Address,
        /// `NAME:0x<tokenId>`.
        token: String,
        /// Amount (wire text, ≤ `weiDecimals`).
        amount: String,
    },
    /// `withdraw3`: perp USDC to Arbitrum through the bridge (fee [`WITHDRAW_FEE_USDC`]).
    Withdraw {
        /// Arbitrum recipient.
        destination: Address,
        /// USDC amount (wire text, ≤ 6 decimals).
        amount: String,
    },
    /// `usdClassTransfer`: USDC between the spot and perp balances of this account.
    UsdClassTransfer {
        /// USDC amount (wire text, ≤ 6 decimals).
        amount: String,
        /// `true` spot → perp, `false` perp → spot.
        to_perp: bool,
    },
    /// `sendAsset` (here: spot → `HyperEVM` through a system address).
    SendAsset {
        /// Recipient (a system address for `HyperCore` → `HyperEVM`).
        destination: Address,
        /// `""` (default perp dex) or `"spot"`.
        source_dex: String,
        /// `""` or `"spot"`.
        destination_dex: String,
        /// `NAME:0x<tokenId>`.
        token: String,
        /// Amount (wire text).
        amount: String,
    },
}

/// The action kinds (wire `type`, EIP-712 primary type).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HcKind {
    /// `usdSend`.
    UsdSend,
    /// `spotSend`.
    SpotSend,
    /// `withdraw3`.
    Withdraw,
    /// `usdClassTransfer`.
    UsdClassTransfer,
    /// `sendAsset`.
    SendAsset,
}

impl HcKind {
    /// Wire `type`.
    #[must_use]
    pub const fn wire_type(self) -> &'static str {
        match self {
            Self::UsdSend => "usdSend",
            Self::SpotSend => "spotSend",
            Self::Withdraw => "withdraw3",
            Self::UsdClassTransfer => "usdClassTransfer",
            Self::SendAsset => "sendAsset",
        }
    }

    /// EIP-712 primary type.
    #[must_use]
    pub const fn primary_type(self) -> &'static str {
        match self {
            Self::UsdSend => "HyperliquidTransaction:UsdSend",
            Self::SpotSend => "HyperliquidTransaction:SpotSend",
            Self::Withdraw => "HyperliquidTransaction:Withdraw",
            Self::UsdClassTransfer => "HyperliquidTransaction:UsdClassTransfer",
            Self::SendAsset => "HyperliquidTransaction:SendAsset",
        }
    }

    /// The SDK field list `(name, type)` in order.
    #[must_use]
    pub const fn fields(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::UsdSend | Self::Withdraw => &[
                ("hyperliquidChain", "string"),
                ("destination", "string"),
                ("amount", "string"),
                ("time", "uint64"),
            ],
            Self::SpotSend => &[
                ("hyperliquidChain", "string"),
                ("destination", "string"),
                ("token", "string"),
                ("amount", "string"),
                ("time", "uint64"),
            ],
            Self::UsdClassTransfer => &[
                ("hyperliquidChain", "string"),
                ("amount", "string"),
                ("toPerp", "bool"),
                ("nonce", "uint64"),
            ],
            Self::SendAsset => &[
                ("hyperliquidChain", "string"),
                ("destination", "string"),
                ("sourceDex", "string"),
                ("destinationDex", "string"),
                ("token", "string"),
                ("amount", "string"),
                ("fromSubAccount", "string"),
                ("nonce", "uint64"),
            ],
        }
    }

    /// `encodeType` of the primary type.
    #[must_use]
    pub fn encode_type(self) -> String {
        let fields: Vec<String> = self
            .fields()
            .iter()
            .map(|(name, kind)| format!("{kind} {name}"))
            .collect();
        format!("{}({})", self.primary_type(), fields.join(","))
    }

    /// `typeHash`.
    #[must_use]
    pub fn type_hash(self) -> [u8; 32] {
        keccak(self.encode_type().as_bytes())
    }

    /// The kind of a primary type.
    #[must_use]
    pub fn from_primary_type(primary: &str) -> Option<Self> {
        [
            Self::UsdSend,
            Self::SpotSend,
            Self::Withdraw,
            Self::UsdClassTransfer,
            Self::SendAsset,
        ]
        .into_iter()
        .find(|kind| kind.primary_type() == primary)
    }

    /// Korean action name (approval, activity).
    #[must_use]
    pub const fn korean(self) -> &'static str {
        match self {
            Self::UsdSend => "USDC 보내기 (HyperCore)",
            Self::SpotSend => "현물 토큰 보내기 (HyperCore)",
            Self::Withdraw => "Arbitrum으로 USDC 출금",
            Self::UsdClassTransfer => "현물↔선물 USDC 이동",
            Self::SendAsset => "HyperEVM으로 이동",
        }
    }
}

/// A field value of the typed data.
#[derive(Clone, Debug, PartialEq, Eq)]
enum HcValue {
    Str(String),
    U64(u64),
    Bool(bool),
}

/// A complete user-signed action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HcAction {
    /// Network (`hyperliquidChain`).
    pub network: HcNetwork,
    /// `signatureChainId` (the EIP-712 domain chain id).
    pub signature_chain_id: u64,
    /// `time` / `nonce` (unix ms; also the request `nonce`).
    pub nonce: u64,
    /// The action fields.
    pub payload: HcPayload,
}

/// Addresses are signed and sent lowercase (docs "Signing": lowercase every address).
fn address_text(address: &Address) -> String {
    address.to_lower_hex()
}

impl HcAction {
    /// A new action signed with the network's [`HcNetwork::signature_chain_id`].
    #[must_use]
    pub const fn new(network: HcNetwork, nonce: u64, payload: HcPayload) -> Self {
        Self {
            network,
            signature_chain_id: network.signature_chain_id(),
            nonce,
            payload,
        }
    }

    /// Kind.
    #[must_use]
    pub const fn kind(&self) -> HcKind {
        match self.payload {
            HcPayload::UsdSend { .. } => HcKind::UsdSend,
            HcPayload::SpotSend { .. } => HcKind::SpotSend,
            HcPayload::Withdraw { .. } => HcKind::Withdraw,
            HcPayload::UsdClassTransfer { .. } => HcKind::UsdClassTransfer,
            HcPayload::SendAsset { .. } => HcKind::SendAsset,
        }
    }

    /// Recipient, if the kind has one.
    #[must_use]
    pub const fn destination(&self) -> Option<Address> {
        match &self.payload {
            HcPayload::UsdSend { destination, .. }
            | HcPayload::SpotSend { destination, .. }
            | HcPayload::Withdraw { destination, .. }
            | HcPayload::SendAsset { destination, .. } => Some(*destination),
            HcPayload::UsdClassTransfer { .. } => None,
        }
    }

    /// Amount wire text.
    #[must_use]
    pub fn amount(&self) -> &str {
        match &self.payload {
            HcPayload::UsdSend { amount, .. }
            | HcPayload::SpotSend { amount, .. }
            | HcPayload::Withdraw { amount, .. }
            | HcPayload::UsdClassTransfer { amount, .. }
            | HcPayload::SendAsset { amount, .. } => amount,
        }
    }

    /// Token wire text (`spotSend`, `sendAsset`).
    #[must_use]
    pub fn token(&self) -> Option<&str> {
        match &self.payload {
            HcPayload::SpotSend { token, .. } | HcPayload::SendAsset { token, .. } => Some(token),
            _ => None,
        }
    }

    /// Structural checks (amount text, token, dex names, nonce).
    ///
    /// # Errors
    ///
    /// [`HcError`].
    pub fn validate(&self) -> Result<(), HcError> {
        if self.nonce == 0 {
            return Err(HcError::Nonce);
        }
        // Spot amounts carry up to `weiDecimals` (≤ 18 here); USDC amounts up to 6.
        let decimals = match self.kind() {
            HcKind::SpotSend | HcKind::SendAsset => 18,
            _ => USD_DECIMALS,
        };
        if !is_wire_amount(self.amount(), decimals) {
            return Err(HcError::Amount);
        }
        if let Some(token) = self.token()
            && !is_token_wire(token)
        {
            return Err(HcError::Token);
        }
        if let HcPayload::SendAsset {
            source_dex,
            destination_dex,
            ..
        } = &self.payload
            && ![source_dex, destination_dex]
                .iter()
                .all(|dex| dex.is_empty() || dex.as_str() == "spot")
        {
            return Err(HcError::Dex);
        }
        Ok(())
    }

    fn values(&self) -> Vec<HcValue> {
        let chain = HcValue::Str(self.network.chain_name().to_owned());
        let nonce = HcValue::U64(self.nonce);
        let s = |text: &str| HcValue::Str(text.to_owned());
        match &self.payload {
            HcPayload::UsdSend {
                destination,
                amount,
            }
            | HcPayload::Withdraw {
                destination,
                amount,
            } => vec![
                chain,
                HcValue::Str(address_text(destination)),
                s(amount),
                nonce,
            ],
            HcPayload::SpotSend {
                destination,
                token,
                amount,
            } => vec![
                chain,
                HcValue::Str(address_text(destination)),
                s(token),
                s(amount),
                nonce,
            ],
            HcPayload::UsdClassTransfer { amount, to_perp } => {
                vec![chain, s(amount), HcValue::Bool(*to_perp), nonce]
            }
            HcPayload::SendAsset {
                destination,
                source_dex,
                destination_dex,
                token,
                amount,
            } => vec![
                chain,
                HcValue::Str(address_text(destination)),
                s(source_dex),
                s(destination_dex),
                s(token),
                s(amount),
                s(""),
                nonce,
            ],
        }
    }

    fn named_values(&self) -> Vec<(&'static str, HcValue)> {
        self.kind()
            .fields()
            .iter()
            .map(|(name, _)| *name)
            .zip(self.values())
            .collect()
    }

    /// `hashStruct(message)`.
    #[must_use]
    pub fn struct_hash(&self) -> [u8; 32] {
        let mut encoded = Vec::with_capacity(32 * 9);
        encoded.extend_from_slice(&self.kind().type_hash());
        for value in self.values() {
            match value {
                HcValue::Str(text) => encoded.extend_from_slice(&keccak(text.as_bytes())),
                HcValue::U64(number) => {
                    encoded.extend_from_slice(U256::from_u64(number).as_be_bytes());
                }
                HcValue::Bool(flag) => {
                    encoded.extend_from_slice(U256::from_u64(u64::from(flag)).as_be_bytes());
                }
            }
        }
        keccak(&encoded)
    }

    /// `domainSeparator` of `HyperliquidSignTransaction` v1 at the action's chain id.
    #[must_use]
    pub fn domain_separator(&self) -> [u8; 32] {
        domain_separator(self.signature_chain_id)
    }

    /// `0x19 0x01 ‖ domainSeparator ‖ hashStruct`.
    #[must_use]
    pub fn preimage(&self) -> [u8; 66] {
        let mut out = [0_u8; 66];
        let (prefix, rest) = out.split_at_mut(2);
        prefix.copy_from_slice(&[0x19, 0x01]);
        let (separator, message) = rest.split_at_mut(32);
        separator.copy_from_slice(&self.domain_separator());
        message.copy_from_slice(&self.struct_hash());
        out
    }

    /// The signed digest `keccak256(preimage)`.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        keccak(&self.preimage())
    }

    /// `"0x"` + lowercase hex of the signature chain id (`"0xa4b1"`, `"0x66eee"`).
    #[must_use]
    pub fn signature_chain_hex(&self) -> String {
        format!("0x{:x}", self.signature_chain_id)
    }

    /// The wire `action` object: `type`, `signatureChainId`, then the typed-data fields.
    #[must_use]
    pub fn action_json(&self) -> Value {
        let mut members = vec![
            ("type".to_owned(), str_value(self.kind().wire_type())),
            (
                "signatureChainId".to_owned(),
                Value::String(self.signature_chain_hex()),
            ),
        ];
        members.extend(
            self.named_values()
                .into_iter()
                .map(|(name, value)| (name.to_owned(), json_of(value))),
        );
        object(members)
    }

    /// The `eth_signTypedData_v4` document of this action (approval details; the tests check
    /// that it validates to the same preimage).
    #[must_use]
    pub fn typed_data_json(&self) -> Value {
        let field = |name: &str, kind: &str| {
            object(vec![
                ("name".to_owned(), str_value(name)),
                ("type".to_owned(), str_value(kind)),
            ])
        };
        let domain_types = Value::Array(vec![
            field("name", "string"),
            field("version", "string"),
            field("chainId", "uint256"),
            field("verifyingContract", "address"),
        ]);
        let primary_types = Value::Array(
            self.kind()
                .fields()
                .iter()
                .map(|(name, kind)| field(name, kind))
                .collect(),
        );
        let message = object(
            self.named_values()
                .into_iter()
                .map(|(name, value)| (name.to_owned(), json_of(value)))
                .collect(),
        );
        object(vec![
            (
                "types".to_owned(),
                object(vec![
                    ("EIP712Domain".to_owned(), domain_types),
                    (self.kind().primary_type().to_owned(), primary_types),
                ]),
            ),
            (
                "primaryType".to_owned(),
                str_value(self.kind().primary_type()),
            ),
            (
                "domain".to_owned(),
                object(vec![
                    ("name".to_owned(), str_value(DOMAIN_NAME)),
                    ("version".to_owned(), str_value(DOMAIN_VERSION)),
                    (
                        "chainId".to_owned(),
                        Value::Number(Number::from_u64(self.signature_chain_id)),
                    ),
                    (
                        "verifyingContract".to_owned(),
                        str_value("0x0000000000000000000000000000000000000000"),
                    ),
                ]),
            ),
            ("message".to_owned(), message),
        ])
    }

    /// The `POST /exchange` body `{action, nonce, signature: {r, s, v}}` for a 65-byte
    /// `r ‖ s ‖ v` signature (`v` 27/28).
    #[must_use]
    pub fn exchange_body(&self, signature: &[u8; 65]) -> Vec<u8> {
        let (r, rest) = signature.split_at(32);
        let (s, v) = rest.split_at(32);
        let v = v.first().copied().unwrap_or(27);
        let signature = object(vec![
            (
                "r".to_owned(),
                Value::String(format!("0x{}", crate::hex::encode(r))),
            ),
            (
                "s".to_owned(),
                Value::String(format!("0x{}", crate::hex::encode(s))),
            ),
            (
                "v".to_owned(),
                Value::Number(Number::from_u64(u64::from(v))),
            ),
        ]);
        yw_json::to_vec(&object(vec![
            ("action".to_owned(), self.action_json()),
            (
                "nonce".to_owned(),
                Value::Number(Number::from_u64(self.nonce)),
            ),
            ("signature".to_owned(), signature),
        ]))
    }

    /// Approval-digest bytes: transcript `"your-wallet/v3/hypercore-action"` v1 of the network,
    /// chain id, the wire action JSON and the EIP-712 preimage.
    #[must_use]
    pub fn digest_bytes(&self) -> Vec<u8> {
        let mut transcript = Transcript::default();
        let _ = transcript.push_bytes(b"your-wallet/v3/hypercore-action");
        transcript.push_u16(1);
        transcript.push_u8(self.network.code());
        transcript.push_u64(self.signature_chain_id);
        let _ = transcript.push_bytes(&yw_json::to_vec(&self.action_json()));
        let _ = transcript.push_bytes(&self.preimage());
        transcript.into_bytes()
    }
}

/// `domainSeparator` of `HyperliquidSignTransaction` v1 at `chain_id`, verifying contract 0.
#[must_use]
pub fn domain_separator(chain_id: u64) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(32 * 5);
    encoded.extend_from_slice(&TYPEHASH_DOMAIN_4);
    encoded.extend_from_slice(&keccak(DOMAIN_NAME.as_bytes()));
    encoded.extend_from_slice(&keccak(DOMAIN_VERSION.as_bytes()));
    encoded.extend_from_slice(U256::from_u64(chain_id).as_be_bytes());
    encoded.extend_from_slice(&[0_u8; 32]);
    keccak(&encoded)
}

fn str_value(text: &str) -> Value {
    Value::String(text.to_owned())
}

fn json_of(value: HcValue) -> Value {
    match value {
        HcValue::Str(text) => Value::String(text),
        HcValue::U64(number) => Value::Number(Number::from_u64(number)),
        HcValue::Bool(flag) => Value::Bool(flag),
    }
}

fn object(members: Vec<(String, Value)>) -> Value {
    Object::from_pairs(members).map_or(Value::Null, Value::Object)
}

// ----- info endpoint ------------------------------------------------------------------------

/// `{"type":"spotMeta"}`.
#[must_use]
pub fn info_spot_meta_body() -> Vec<u8> {
    yw_json::to_vec(&object(vec![("type".to_owned(), str_value("spotMeta"))]))
}

/// `{"type":"clearinghouseState","user":"0x…"}` (perp account summary).
#[must_use]
pub fn info_perp_state_body(user: &Address) -> Vec<u8> {
    yw_json::to_vec(&object(vec![
        ("type".to_owned(), str_value("clearinghouseState")),
        ("user".to_owned(), Value::String(address_text(user))),
    ]))
}

/// `{"type":"spotClearinghouseState","user":"0x…"}` (spot balances).
#[must_use]
pub fn info_spot_state_body(user: &Address) -> Vec<u8> {
    yw_json::to_vec(&object(vec![
        ("type".to_owned(), str_value("spotClearinghouseState")),
        ("user".to_owned(), Value::String(address_text(user))),
    ]))
}

/// The `HyperEVM` link of a spot token (`spotMeta.tokens[].evmContract`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HcEvmLink {
    /// ERC-20 contract on `HyperEVM` (the zero address for HYPE, which is native there).
    pub address: Address,
    /// `evm_extra_wei_decimals`: EVM decimals − `weiDecimals` (−2..=18).
    pub extra_wei_decimals: i8,
}

impl HcEvmLink {
    /// Decimals of the token on `HyperEVM`.
    #[must_use]
    pub fn evm_decimals(&self, wei_decimals: u8) -> Option<u8> {
        u8::try_from(i16::from(wei_decimals).checked_add(i16::from(self.extra_wei_decimals))?).ok()
    }
}

/// One spot token of `spotMeta`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HcToken {
    /// `name` (untrusted text, escaped at display).
    pub name: String,
    /// `index` (system address, balances).
    pub index: u32,
    /// `tokenId` (`0x` + 32 hex).
    pub token_id: String,
    /// `szDecimals`.
    pub sz_decimals: u8,
    /// `weiDecimals` (amount precision on `HyperCore`).
    pub wei_decimals: u8,
    /// `HyperEVM` link.
    pub evm: Option<HcEvmLink>,
    /// `fullName`.
    pub full_name: Option<String>,
}

impl HcToken {
    /// `NAME:0x<tokenId>`.
    #[must_use]
    pub fn wire(&self) -> String {
        format!("{}:{}", self.name, self.token_id)
    }

    /// Whether this is HYPE (its system address is [`HYPE_SYSTEM_ADDRESS`]).
    #[must_use]
    pub fn is_hype(&self) -> bool {
        self.name == "HYPE"
            && self
                .evm
                .is_some_and(|link| link.address == Address::from_bytes([0; 20]))
    }

    /// The system address used for `HyperCore` ↔ `HyperEVM` transfers of this token.
    #[must_use]
    pub fn system_address(&self) -> Address {
        if self.is_hype() {
            HYPE_SYSTEM_ADDRESS
        } else {
            system_address(self.index)
        }
    }

    /// Decimals a `HyperCore` → `HyperEVM` amount may have without a burned remainder: the
    /// smaller of `weiDecimals` and the EVM decimals ("Non-round amounts are burned").
    #[must_use]
    pub fn evm_transfer_decimals(&self) -> Option<u8> {
        let link = self.evm?;
        Some(self.wei_decimals.min(link.evm_decimals(self.wei_decimals)?))
    }
}

fn get<'v>(object: &'v Object, key: &str) -> Result<&'v Value, HcError> {
    object.get(key).ok_or(HcError::Response)
}

fn small_u8(value: &Value) -> Result<u8, HcError> {
    value
        .as_number()
        .and_then(Number::as_u64)
        .and_then(|number| u8::try_from(number).ok())
        .filter(|number| *number <= 36)
        .ok_or(HcError::Response)
}

fn token_id(value: &Value) -> Result<String, HcError> {
    let text = value.as_str().ok_or(HcError::Response)?;
    let ok = text.len() == 34
        && text.strip_prefix("0x").is_some_and(|hex| {
            hex.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
    if ok {
        Ok(text.to_owned())
    } else {
        Err(HcError::Response)
    }
}

fn evm_link(value: &Value) -> Result<Option<HcEvmLink>, HcError> {
    if value.is_null() {
        return Ok(None);
    }
    let object = value.as_object().ok_or(HcError::Response)?;
    let address = get(object, "address")?
        .as_str()
        .and_then(|text| parse_address(text).ok())
        .ok_or(HcError::Response)?;
    let extra = get(object, "evm_extra_wei_decimals")?
        .as_number()
        .and_then(Number::as_i64)
        .and_then(|number| i8::try_from(number).ok())
        .filter(|number| (-2..=18).contains(number))
        .ok_or(HcError::Response)?;
    Ok(Some(HcEvmLink {
        address,
        extra_wei_decimals: extra,
    }))
}

/// Parses `spotMeta` (`tokens[]`; `universe` is not used). Tokens with a malformed entry make the
/// whole response invalid (never guess decimals).
///
/// # Errors
///
/// [`HcError::Response`].
pub fn parse_spot_meta(value: &Value) -> Result<Vec<HcToken>, HcError> {
    let object = value.as_object().ok_or(HcError::Response)?;
    let tokens = get(object, "tokens")?.as_array().ok_or(HcError::Response)?;
    let mut out = Vec::with_capacity(tokens.len());
    for token in tokens {
        let token = token.as_object().ok_or(HcError::Response)?;
        let name = get(token, "name")?.as_str().ok_or(HcError::Response)?;
        if name.is_empty() || name.len() > 64 {
            return Err(HcError::Response);
        }
        let index = get(token, "index")?
            .as_number()
            .and_then(Number::as_u64)
            .and_then(|number| u32::try_from(number).ok())
            .ok_or(HcError::Response)?;
        let full_name = match token.get("fullName") {
            Some(Value::String(text)) if text.len() <= 128 => Some(text.clone()),
            Some(Value::Null) | None => None,
            Some(_) => return Err(HcError::Response),
        };
        out.push(HcToken {
            name: name.to_owned(),
            index,
            token_id: token_id(get(token, "tokenId")?)?,
            sz_decimals: small_u8(get(token, "szDecimals")?)?,
            wei_decimals: small_u8(get(token, "weiDecimals")?)?,
            evm: match token.get("evmContract") {
                Some(value) => evm_link(value)?,
                None => None,
            },
            full_name,
        });
    }
    Ok(out)
}

/// Whether `text` is an API decimal (`"14.625485"`, `"0.0"`, `"-1.5"`).
fn is_api_decimal(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    let (integer, fraction) = digits.split_once('.').unwrap_or((digits, "0"));
    (1..=40).contains(&text.len())
        && !integer.is_empty()
        && !fraction.is_empty()
        && integer.bytes().all(|byte| byte.is_ascii_digit())
        && fraction.bytes().all(|byte| byte.is_ascii_digit())
}

fn decimal(object: &Object, key: &str) -> Result<String, HcError> {
    let text = get(object, key)?.as_str().ok_or(HcError::Response)?;
    if is_api_decimal(text) {
        Ok(text.to_owned())
    } else {
        Err(HcError::Response)
    }
}

/// One spot balance of `spotClearinghouseState.balances[]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HcSpotBalance {
    /// `coin` (token name).
    pub coin: String,
    /// `token` (index into `spotMeta.tokens`).
    pub token: u32,
    /// `total` (decimal text).
    pub total: String,
    /// `hold` (decimal text, reserved by open orders).
    pub hold: String,
}

/// Parses `spotClearinghouseState`.
///
/// # Errors
///
/// [`HcError::Response`].
pub fn parse_spot_state(value: &Value) -> Result<Vec<HcSpotBalance>, HcError> {
    let object = value.as_object().ok_or(HcError::Response)?;
    let balances = get(object, "balances")?
        .as_array()
        .ok_or(HcError::Response)?;
    let mut out = Vec::with_capacity(balances.len());
    for balance in balances {
        let balance = balance.as_object().ok_or(HcError::Response)?;
        let coin = get(balance, "coin")?.as_str().ok_or(HcError::Response)?;
        if coin.is_empty() || coin.len() > 64 {
            return Err(HcError::Response);
        }
        out.push(HcSpotBalance {
            coin: coin.to_owned(),
            token: get(balance, "token")?
                .as_number()
                .and_then(Number::as_u64)
                .and_then(|number| u32::try_from(number).ok())
                .ok_or(HcError::Response)?,
            total: decimal(balance, "total")?,
            hold: decimal(balance, "hold")?,
        });
    }
    Ok(out)
}

/// The perp account summary of `clearinghouseState`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HcPerpState {
    /// `marginSummary.accountValue` (USDC, decimal text).
    pub account_value: String,
    /// `withdrawable` (USDC, decimal text).
    pub withdrawable: String,
    /// Number of open positions (`assetPositions`).
    pub positions: usize,
}

/// Parses `clearinghouseState`.
///
/// # Errors
///
/// [`HcError::Response`].
pub fn parse_perp_state(value: &Value) -> Result<HcPerpState, HcError> {
    let object = value.as_object().ok_or(HcError::Response)?;
    let summary = get(object, "marginSummary")?
        .as_object()
        .ok_or(HcError::Response)?;
    Ok(HcPerpState {
        account_value: decimal(summary, "accountValue")?,
        withdrawable: decimal(object, "withdrawable")?,
        positions: get(object, "assetPositions")?
            .as_array()
            .ok_or(HcError::Response)?
            .len(),
    })
}

/// The `/exchange` answer: `{"status":"ok","response":{"type":"default"}}` or
/// `{"status":"err","response":"<message>"}` (HTTP 200 either way).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HcExchangeReply {
    /// `status: ok`.
    Ok,
    /// `status: err` with the server message (untrusted text, bounded).
    Err(String),
}

/// Parses an `/exchange` answer.
///
/// # Errors
///
/// [`HcError::Response`].
pub fn parse_exchange_reply(value: &Value) -> Result<HcExchangeReply, HcError> {
    let object = value.as_object().ok_or(HcError::Response)?;
    match get(object, "status")?.as_str() {
        Some("ok") => Ok(HcExchangeReply::Ok),
        Some("err") => {
            let message = match object.get("response") {
                Some(Value::String(text)) => text.chars().take(300).collect(),
                _ => String::new(),
            };
            Ok(HcExchangeReply::Err(message))
        }
        _ => Err(HcError::Response),
    }
}
