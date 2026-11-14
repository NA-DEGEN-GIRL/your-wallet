//! Send-form rules (spec/04 §2.7, §2.15): recipient address checks with address-book notes and
//! look-alike (address-poisoning) detection, amount parsing (`parse_units`, archive
//! `demo/sepolia-wallet/src/erc20.rs:222-266`), funds checks and the fee quote.

use std::collections::BTreeSet;

use yw_core::evm::address::{Address, AddressError, parse_address, poisoning_look_alike};
pub use yw_core::evm::address::{KnownAddress, LOOK_ALIKE_MIN_ENDS, look_alike};
use yw_core::evm::amount::{U256, format_amount, format_gwei, format_units, parse_units};
use yw_core::evm::chain::ChainInfo;
use yw_core::evm::decode::token_transfer_recipient;
use yw_core::evm::fee::{
    GasEstimate, check_caps_with_l1, max_total_fee, max_total_fee_with_l1, plan_gas_limit,
    suggest_fees,
};
use yw_core::evm::tx::Eip1559Tx;
use yw_core::lang::Lang;

use super::prepare::SendIntent;
use super::{ChainCache, ChainCheck, ChainJob, Clock, SharedTransport};
use crate::errors::ErrorCode;
use crate::rpc::evm::{self as rpc, EstimateOutcome};
use crate::rpc::{RpcClient, classify};

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
    /// The fixed sentence in `lang` (names are user-entered labels, never translated).
    #[must_use]
    pub fn text_in(&self, lang: Lang) -> String {
        match self {
            Self::SameAsSender => text::SAME_AS_SENDER.get(lang).to_owned(),
            Self::Book { name, verified } => {
                if *verified {
                    text::BOOK_VERIFIED.fill(lang, [name])
                } else {
                    text::BOOK.fill(lang, [name])
                }
            }
            Self::Mine { label } => text::MINE.fill(lang, [label]),
            Self::LookAlike {
                name,
                history,
                prefix,
                suffix,
            } => {
                let ends = match (*prefix, *suffix) {
                    (0, suffix) => text::ENDS_SUFFIX.fill(lang, [&suffix.to_string()]),
                    (prefix, 0) => text::ENDS_PREFIX.fill(lang, [&prefix.to_string()]),
                    (prefix, suffix) => {
                        text::ENDS_BOTH.fill(lang, [&prefix.to_string(), &suffix.to_string()])
                    }
                };
                let whom = if *history {
                    text::WHOM_SENT.fill(lang, [name])
                } else {
                    text::WHOM_NAMED.fill(lang, [name])
                };
                text::LOOK_ALIKE.fill(lang, [&whom, &ends])
            }
            Self::NotInBook => text::NOT_IN_BOOK.get(lang).to_owned(),
            Self::Contract => text::CONTRACT.get(lang).to_owned(),
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

/// Recipient checks (spec/04 §2.15 rows 1–8; row 9 needs `eth_getCode`). Book entries and own
/// accounts give exact-match notes; every entry, history included, is compared by
/// [`look_alike`] — also beside an exact match with an unverified book entry or a past
/// recipient (a poisoned address saved to the book must not silence the warning against the
/// address it imitates). Only an exact own account or verified book entry skips the comparison
/// ([`KnownAddress::trusted`]).
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
    let exact = known
        .iter()
        .find(|entry| !entry.history && entry.address == address);
    if let Some(entry) = exact {
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
    }
    if let Some((entry, (prefix, suffix))) = poisoning_look_alike(known, &address) {
        notes.push(AddressNote::LookAlike {
            name: entry.name.clone(),
            history: entry.history,
            prefix,
            suffix,
        });
    } else if exact.is_none() {
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

/// `최대` for the native asset: `balance − max_total` (spec/04 §2.7), where `max_total` is the
/// quote's `gas_limit × max_fee` plus the OP-stack L1 part (spec/03 §3.4a).
///
/// # Errors
///
/// [`ErrorCode::Inp012`] when nothing is left.
pub fn max_native(balance: &U256, max_total: &U256) -> Result<U256, ErrorCode> {
    balance
        .checked_sub(*max_total)
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
    /// `gas_limit × maxFee`, plus the OP-stack L1 data fee maximum (spec/03 §3.4a).
    pub max_total: U256,
    /// E-TX-001 cap violation text (blocks `검토`).
    pub cap_violation: Option<String>,
    /// Gas estimation failed (E37 will follow in the approval).
    pub estimate_failed: bool,
}

impl Quote {
    /// The fixed line in `lang`.
    #[must_use]
    pub fn line_in(&self, lang: Lang, chain: &ChainInfo) -> String {
        let native =
            |value: &U256| format_amount(value, chain.native_decimals, &chain.native_symbol);
        let l1 = max_total_fee(self.gas_limit, &self.max_fee_per_gas)
            .and_then(|l2| self.max_total.checked_sub(l2))
            .filter(|l1| !l1.is_zero());
        let l1_text = l1.map_or_else(String::new, |l1| text::QUOTE_L1.fill(lang, [&native(&l1)]));
        text::QUOTE.fill(
            lang,
            [
                &native(&self.max_total),
                &format_units(&U256::from_u64(self.gas_limit), 0),
                &format_gwei(&self.max_fee_per_gas),
                &l1_text,
            ],
        )
    }
}

/// Send-form notes and the fee line (spec/04 §2.7, §2.15; English spec/14 §5).
pub mod text {
    yw_core::texts! {
        SAME_AS_SENDER = "보내는 계정과 같은 주소입니다." / "Same address as the sending account.";
        BOOK_VERIFIED(1) = "주소록: {0} ✓ 확인됨" / "Address book: {0} ✓ verified";
        BOOK(1) = "주소록: {0}" / "Address book: {0}";
        MINE(1) = "내 계정: {0}" / "My account: {0}";
        ENDS_SUFFIX(1) = "끝 {0}자" / "last {0} characters";
        ENDS_PREFIX(1) = "앞 {0}자" / "first {0} characters";
        ENDS_BOTH(2) = "앞 {0}자·끝 {1}자" / "first {0} and last {1} characters";
        WHOM_SENT(1) = "보낸 내역에 있는 주소({0})와" / "an address in your sent history ({0})";
        WHOM_NAMED(1) = "'{0}'과" / "'{0}'";
        /// `{0}` = `WHOM_*`, `{1}` = `ENDS_*`.
        LOOK_ALIKE(2) = "{0} {1}가 같지만 다른 주소입니다. 주소 오염 공격일 수 있습니다."
            / "Same {1} as {0}, but a different address. It may be an address-poisoning attack.";
        NOT_IN_BOOK = "주소록에 없는 주소입니다. 주소 전체를 확인하세요."
            / "This address is not in your address book. Check the whole address.";
        CONTRACT = "컨트랙트 주소입니다. 받는 쪽이 이 자산을 처리할 수 있는지 확인하세요."
            / "This is a contract address. Check that the recipient can handle this asset.";
        /// `{0}` max total, `{1}` gas limit, `{2}` max fee per gas, `{3}` the `QUOTE_L1` part.
        QUOTE(4) = "예상 최대 수수료: {0} (가스 한도 {1} × 최대 {2}{3})"
            / "Expected max fee: {0} (gas limit {1} × max {2}{3})";
        QUOTE_L1(1) = " + L1 데이터 수수료 최대 {0}" / " + L1 data fee up to {0}";
    }
}

/// Fee quote: chain check, `eth_feeHistory`, `eth_estimateGas`, §3.5 gas plan and the caps.
///
/// # Errors
///
/// The classified RPC error, E-RPC-006/E-CHN-008 for a mismatch, E-RPC-005 for bad fee history.
#[expect(
    clippy::too_many_arguments,
    reason = "the worker's transport, cache, clock and limits plus the form's language and intent"
)]
pub fn quote(
    lang: yw_core::lang::Lang,
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
    let plan = plan_gas_limit(lang, gas, intent.dapp_gas, &fees, &chain.caps, &chain.info);
    let quoted = Eip1559Tx {
        gas_limit: plan.gas_limit,
        ..probe
    };
    let l1_max = super::prepare::l1_fee_lookup(&client, &chain.url, &chain.info, &quoted).max();
    let max_total =
        max_total_fee_with_l1(plan.gas_limit, &fees.max_fee_per_gas, &l1_max).unwrap_or(U256::MAX);
    let cap_violation = check_caps_with_l1(&fees, plan.gas_limit, &l1_max, &chain.caps)
        .err()
        .map(|violation| {
            let text = violation.warning(lang, &chain.info).text;
            format!(
                "{} {}",
                ErrorCode::Tx001.text_in(lang),
                text.replace('\n', " · ")
            )
        });
    Ok(Quote {
        gas_limit: plan.gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_total,
        cap_violation,
        estimate_failed: failed,
    })
}
