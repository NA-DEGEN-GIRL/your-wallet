//! Send-form rules (spec/04 §2.7, §2.15): recipient address checks with address-book notes and
//! look-alike (address-poisoning) detection, amount parsing (`parse_units`, archive
//! `demo/sepolia-wallet/src/erc20.rs:222-266`), funds checks and the fee quote.

use std::collections::BTreeSet;

use yw_core::evm::address::{Address, AddressError, parse_address};
use yw_core::evm::amount::{U256, format_amount, format_gwei, format_units, parse_units};
use yw_core::evm::chain::ChainInfo;
use yw_core::evm::decode::token_transfer_recipient;
use yw_core::evm::fee::{GasEstimate, check_caps, max_total_fee, plan_gas_limit, suggest_fees};
use yw_core::evm::tx::Eip1559Tx;

use super::prepare::SendIntent;
use super::{ChainCache, ChainCheck, ChainJob, Clock, SharedTransport};
use crate::errors::ErrorCode;
use crate::rpc::evm::{self as rpc, EstimateOutcome};
use crate::rpc::{RpcClient, classify};

/// An address the user knows (address book, own account or sent history).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownAddress {
    /// Address.
    pub address: Address,
    /// Book name or account label (the lowercase address for a history entry).
    pub name: String,
    /// Book entry marked verified.
    pub verified: bool,
    /// One of the wallet's own accounts.
    pub mine: bool,
    /// A past recipient (journal record or activity row): compared for look-alikes only — an
    /// exact match gives no book note and it is not offered by the picker.
    pub history: bool,
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
    /// W-ADDR-3 look-alike (see [`look_alike`]).
    LookAlike {
        /// The similar entry's name (its lowercase address for a history entry).
        name: String,
        /// The similar entry is a past recipient, not a book entry or own account.
        history: bool,
        /// Equal leading hex digits (after `0x`).
        prefix: usize,
        /// Equal trailing hex digits.
        suffix: usize,
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
            Self::LookAlike {
                name,
                history,
                prefix,
                suffix,
            } => {
                let ends = match (*prefix, *suffix) {
                    (0, suffix) => format!("끝 {suffix}자"),
                    (prefix, 0) => format!("앞 {prefix}자"),
                    (prefix, suffix) => format!("앞 {prefix}자·끝 {suffix}자"),
                };
                let whom = if *history {
                    format!("보낸 내역에 있는 주소({name})와")
                } else {
                    format!("'{name}'과")
                };
                format!("{whom} {ends}가 같지만 다른 주소입니다. 주소 오염 공격일 수 있습니다.")
            }
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

/// Recipients of a sent transaction for the history entries: its `to`, and for an ERC-20
/// `transfer(to, amount)` / `transferFrom(from, to, amount)` call the decoded token recipient
/// (strict decode, [`token_transfer_recipient`]).
#[must_use]
pub fn tx_recipients(tx: &Eip1559Tx) -> Vec<Address> {
    let mut out = vec![tx.to];
    if let Some(recipient) = token_transfer_recipient(&tx.data)
        && recipient != tx.to
    {
        out.push(recipient);
    }
    out
}

/// Appends past recipients as history entries ([`KnownAddress::history`]), skipping the zero
/// address and any address already listed (book, own account or an earlier history entry).
pub fn add_history(known: &mut Vec<KnownAddress>, recipients: impl IntoIterator<Item = Address>) {
    let mut seen: BTreeSet<Address> = known.iter().map(|entry| entry.address).collect();
    for address in recipients {
        if address != Address::from_bytes([0; 20]) && seen.insert(address) {
            known.push(KnownAddress {
                address,
                name: address.to_lower_hex(),
                verified: false,
                mine: false,
                history: true,
            });
        }
    }
}

/// Matching end digits (prefix + suffix) that make two different addresses look-alikes.
pub const LOOK_ALIKE_MIN_ENDS: usize = 6;

fn nibbles(address: &Address) -> impl DoubleEndedIterator<Item = u8> + '_ {
    address
        .as_bytes()
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
}

/// W-ADDR-3 address-poisoning check: `Some((prefix, suffix))` when `typed` is a look-alike of
/// `known`.
///
/// Rule: the two addresses differ (so some middle digit mismatches), and there is a split
/// `p + s ≥ 6` where the first `p` and the last `s` of the 40 hex digits are equal (after `0x`,
/// case-insensitive: checksum casing is ignored). Any split counts — 6+0, 4+2, 3+3, 2+4, 0+6 —
/// because poisoners grind whichever ends a wallet shows, and some show only the head or only
/// the tail. Checking every split is the same as `P + S ≥ 6` for the longest common prefix `P`
/// and suffix `S`, which are returned.
///
/// False positives: for a random 40-digit address, `P(P + S ≥ 6) = 16⁻⁶ · (1 + 6 · 15/16) ≈
/// 3.9e-7` per known address (≈ the 7 splits × 16⁻⁶ ≈ 4e-7 union bound). Even with the full
/// activity history (3,000 rows) plus book and accounts that stays near 1e-3 per typed
/// address, and a false positive only asks for the `주소 전체를 직접 확인했습니다` checkbox; so no
/// per-side minimum is imposed. Five matching end digits (e.g. 3+2) are not flagged: that
/// would be ≈ 16⁻⁵ · 5.7 ≈ 5.4e-6 per known address, i.e. ~1.6 % of honest addresses warned
/// against a full history.
#[must_use]
pub fn look_alike(known: &Address, typed: &Address) -> Option<(usize, usize)> {
    if known == typed {
        return None;
    }
    let prefix = nibbles(known)
        .zip(nibbles(typed))
        .take_while(|(a, b)| a == b)
        .count();
    let suffix = nibbles(known)
        .rev()
        .zip(nibbles(typed).rev())
        .take_while(|(a, b)| a == b)
        .count();
    (prefix.saturating_add(suffix) >= LOOK_ALIKE_MIN_ENDS).then_some((prefix, suffix))
}

/// The look-alike entry with the most matching end digits; on a tie the earlier entry (book and
/// own accounts come before history).
fn closest_look_alike<'k>(
    known: &'k [KnownAddress],
    address: &Address,
) -> Option<(&'k KnownAddress, (usize, usize))> {
    let mut best: Option<(&KnownAddress, (usize, usize))> = None;
    for entry in known {
        if let Some(ends) = look_alike(&entry.address, address)
            && best.is_none_or(|(_, (p, s))| ends.0.saturating_add(ends.1) > p.saturating_add(s))
        {
            best = Some((entry, ends));
        }
    }
    best
}

/// Recipient checks (spec/04 §2.15 rows 1–8; row 9 needs `eth_getCode`). Book entries and own
/// accounts give exact-match notes; every entry, history included, is compared by
/// [`look_alike`].
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
    if let Some(entry) = known
        .iter()
        .find(|entry| !entry.history && entry.address == address)
    {
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
    } else if let Some((entry, (prefix, suffix))) = closest_look_alike(known, &address) {
        notes.push(AddressNote::LookAlike {
            name: entry.name.clone(),
            history: entry.history,
            prefix,
            suffix,
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
