//! Send-form rules (spec/04 §2.7, §2.15): recipient address checks with address-book notes and
//! look-alike detection, amount parsing (`parse_units`, archive
//! `demo/sepolia-wallet/src/erc20.rs:222-266`), funds checks and the fee quote.

use yw_core::evm::address::{Address, AddressError, parse_address};
use yw_core::evm::amount::{U256, format_amount, format_gwei, format_units, parse_units};
use yw_core::evm::chain::ChainInfo;
use yw_core::evm::fee::{GasEstimate, check_caps, max_total_fee, plan_gas_limit, suggest_fees};
use yw_core::evm::tx::Eip1559Tx;

use super::prepare::SendIntent;
use super::{ChainCache, ChainCheck, ChainJob, Clock, SharedTransport};
use crate::errors::ErrorCode;
use crate::rpc::evm::{self as rpc, EstimateOutcome};
use crate::rpc::{RpcClient, classify};

/// An address the user knows (address book or own account).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownAddress {
    /// Address.
    pub address: Address,
    /// Book name or account label.
    pub name: String,
    /// Book entry marked verified.
    pub verified: bool,
    /// One of the wallet's own accounts.
    pub mine: bool,
}

/// A note shown under the recipient (spec/04 §2.15 rows 5–8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressNote {
    /// W-ADDR-1.
    SameAsSender,
    /// Exact address-book match.
    Book {
        /// Name.
        name: String,
        /// Verified.
        verified: bool,
    },
    /// Exact own-account match.
    Mine {
        /// Label.
        label: String,
    },
    /// W-ADDR-3 look-alike (first and last 4 hex digits equal).
    LookAlike {
        /// The similar entry's name.
        name: String,
    },
    /// W-ADDR-2.
    NotInBook,
    /// W-ADDR-4 (native asset to a contract; from `eth_getCode`).
    Contract,
}

impl AddressNote {
    /// The fixed sentence (names are user-entered labels).
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::SameAsSender => "보내는 계정과 같은 주소입니다.".to_owned(),
            Self::Book { name, verified } => {
                if *verified {
                    format!("주소록: {name} ✓ 확인됨")
                } else {
                    format!("주소록: {name}")
                }
            }
            Self::Mine { label } => format!("내 계정: {label}"),
            Self::LookAlike { name } => format!(
                "'{name}'과 앞 4자·끝 4자가 같지만 다른 주소입니다. 주소 오염 공격일 수 있습니다."
            ),
            Self::NotInBook => "주소록에 없는 주소입니다. 주소 전체를 확인하세요.".to_owned(),
            Self::Contract => {
                "컨트랙트 주소입니다. 받는 쪽이 이 자산을 처리할 수 있는지 확인하세요.".to_owned()
            }
        }
    }

    /// W-ADDR-3 needs the `주소 전체를 직접 확인했습니다` checkbox.
    #[must_use]
    pub const fn needs_ack(&self) -> bool {
        matches!(self, Self::LookAlike { .. })
    }

    /// Shown as a warning (yellow) rather than information.
    #[must_use]
    pub const fn is_warning(&self) -> bool {
        matches!(
            self,
            Self::SameAsSender | Self::LookAlike { .. } | Self::NotInBook | Self::Contract
        )
    }
}

fn look_alike(a: &Address, b: &Address) -> bool {
    let a = a.to_lower_hex();
    let b = b.to_lower_hex();
    a != b && a.get(2..6) == b.get(2..6) && a.get(38..42) == b.get(38..42)
}

/// Recipient checks (spec/04 §2.15 rows 1–8; row 9 needs `eth_getCode`).
///
/// # Errors
///
/// E-INP-009 format, E-INP-010 checksum, E-INP-014 zero address, E-INP-015 token contract.
pub fn check_recipient(
    text: &str,
    sender: &Address,
    token: Option<&Address>,
    known: &[KnownAddress],
) -> Result<(Address, Vec<AddressNote>), ErrorCode> {
    let trimmed = text.trim_matches([' ', '\t', '\r', '\n']);
    let address = parse_address(trimmed).map_err(|error| match error {
        AddressError::BadChecksum => ErrorCode::Inp010,
        AddressError::InvalidFormat => ErrorCode::Inp009,
    })?;
    if address == Address::from_bytes([0; 20]) {
        return Err(ErrorCode::Inp014);
    }
    if token == Some(&address) {
        return Err(ErrorCode::Inp015);
    }
    let mut notes = Vec::new();
    if address == *sender {
        notes.push(AddressNote::SameAsSender);
    }
    if let Some(entry) = known.iter().find(|entry| entry.address == address) {
        notes.push(if entry.mine {
            AddressNote::Mine {
                label: entry.name.clone(),
            }
        } else {
            AddressNote::Book {
                name: entry.name.clone(),
                verified: entry.verified,
            }
        });
    } else if let Some(entry) = known
        .iter()
        .find(|entry| look_alike(&entry.address, &address))
    {
        notes.push(AddressNote::LookAlike {
            name: entry.name.clone(),
        });
    } else {
        notes.push(AddressNote::NotInBook);
    }
    Ok((address, notes))
}

/// Amount input (spec/04 §2.15): `parse_units`, more than zero.
///
/// # Errors
///
/// [`ErrorCode::Inp011`].
pub fn parse_amount(text: &str, decimals: u8) -> Result<U256, ErrorCode> {
    let amount = parse_units(text, decimals).map_err(|_| ErrorCode::Inp011)?;
    if amount.is_zero() {
        return Err(ErrorCode::Inp011);
    }
    Ok(amount)
}

/// Funds rule (spec/04 §2.15): native `amount + max fee ≤ balance`; token `amount ≤ token
/// balance` and `max fee ≤ native balance`.
///
/// # Errors
///
/// [`ErrorCode::Inp012`].
pub fn check_funds(
    native: bool,
    amount: &U256,
    max_fee: &U256,
    native_balance: &U256,
    token_balance: Option<&U256>,
) -> Result<(), ErrorCode> {
    let ok = if native {
        amount
            .checked_add(*max_fee)
            .is_some_and(|total| total <= *native_balance)
    } else {
        token_balance.is_some_and(|balance| amount <= balance) && max_fee <= native_balance
    };
    if ok { Ok(()) } else { Err(ErrorCode::Inp012) }
}

/// `최대` for the native asset: `balance − gas_limit × max_fee` (spec/04 §2.7).
///
/// # Errors
///
/// [`ErrorCode::Inp012`] when nothing is left.
pub fn max_native(
    balance: &U256,
    gas_limit: u64,
    max_fee_per_gas: &U256,
) -> Result<U256, ErrorCode> {
    let fee = max_total_fee(gas_limit, max_fee_per_gas).ok_or(ErrorCode::Inp012)?;
    balance
        .checked_sub(fee)
        .filter(|left| !left.is_zero())
        .ok_or(ErrorCode::Inp012)
}

/// The send form's fee quote (spec/04 §2.7: "예상 최대 수수료 …").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Quote {
    /// Gas limit.
    pub gas_limit: u64,
    /// `maxFeePerGas`.
    pub max_fee_per_gas: U256,
    /// `gas_limit × maxFee`.
    pub max_total: U256,
    /// E-TX-001 cap violation text (blocks `검토`).
    pub cap_violation: Option<String>,
    /// Gas estimation failed (E37 will follow in the approval).
    pub estimate_failed: bool,
}

impl Quote {
    /// The fixed line.
    #[must_use]
    pub fn line(&self, chain: &ChainInfo) -> String {
        format!(
            "예상 최대 수수료: {} (가스 한도 {} × 최대 {})",
            format_amount(&self.max_total, chain.native_decimals, &chain.native_symbol),
            format_units(&U256::from_u64(self.gas_limit), 0),
            format_gwei(&self.max_fee_per_gas)
        )
    }
}

/// Fee quote: chain check, `eth_feeHistory`, `eth_estimateGas`, §3.5 gas plan and the caps.
///
/// # Errors
///
/// The classified RPC error, E-RPC-006/E-CHN-008 for a mismatch, E-RPC-005 for bad fee history.
pub fn quote(
    transport: &SharedTransport,
    cache: &mut ChainCache,
    chain: &ChainJob,
    from: &Address,
    intent: &SendIntent,
    clock: &dyn Clock,
    retry_delay_ms: u64,
) -> Result<Quote, ErrorCode> {
    let client = RpcClient::new(&**transport);
    match cache.ensure(&client, &chain.url, &chain.info, clock, retry_delay_ms) {
        ChainCheck::Verified { .. } => {}
        other => return Err(other.code().unwrap_or(ErrorCode::App009)),
    }
    let history = rpc::fee_history(&client, &chain.url, 10).map_err(classify)?;
    let fees = suggest_fees(&history, &chain.info).map_err(|_| ErrorCode::Rpc005)?;
    let probe = Eip1559Tx {
        chain_id: chain.info.chain_id,
        nonce: 0,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        max_fee_per_gas: fees.max_fee_per_gas,
        gas_limit: 0,
        to: intent.to,
        value: intent.value,
        data: intent.data.clone(),
        access_list: intent.access_list.clone(),
    };
    let estimate = rpc::estimate_gas(&client, &chain.url, from, &probe);
    let failed = matches!(estimate, EstimateOutcome::Failed { .. });
    let gas = match &estimate {
        EstimateOutcome::Estimated(value) => GasEstimate::Estimated(*value),
        EstimateOutcome::Failed { revert_data, .. } => GasEstimate::Failed {
            revert_data: revert_data.as_deref(),
        },
    };
    let plan = plan_gas_limit(gas, intent.dapp_gas, &fees, &chain.caps, &chain.info);
    let max_total = max_total_fee(plan.gas_limit, &fees.max_fee_per_gas).unwrap_or(U256::MAX);
    let cap_violation = check_caps(&fees, plan.gas_limit, &chain.caps)
        .err()
        .map(|violation| {
            let text = violation.warning(&chain.info).text;
            format!("{} {}", ErrorCode::Tx001.text(), text.replace('\n', " · "))
        });
    Ok(Quote {
        gas_limit: plan.gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_total,
        cap_violation,
        estimate_failed: failed,
    })
}
