//! Send planning (spec/12 §7): coin selection over the account's confirmed transparent UTXOs,
//! one recipient output, change back to the same address, the ZIP 317 fee and the checked
//! consensus fields.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use super::account::ZecAccount;
use super::address::{ZecDest, ZecRecipient};
use super::fee::planned_fee;
use super::sighash::ZecPrevout;
use super::tx::{MAX_MONEY, ZecOutPoint, ZecTx, ZecTxIn, ZecTxOut};
use super::upgrade::TxConsensus;
use super::{
    ZEC_DUST, ZEC_FEE_ABS_CAP, ZEC_MAX_INPUTS, ZEC_SEQUENCE, format_zec, format_zec_and_zats,
};

/// One candidate UTXO of our address (from the node's `getaddressutxos` or the indexer).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ZecUtxo {
    /// Outpoint.
    pub outpoint: ZecOutPoint,
    /// Value in zatoshis (committed by the `SIGHASH_ALL` digest, spec/12 §5.3).
    pub value: u64,
    /// Block height, `None` while unconfirmed.
    pub height: Option<u32>,
    /// A coinbase output (transparent coinbase outputs may not be spent to transparent outputs;
    /// never selected).
    pub coinbase: bool,
}

/// What to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZecAmount {
    /// Exactly this many zatoshis to the recipient.
    Exact(u64),
    /// Everything spendable minus the fee.
    Max,
}

/// A send request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZecSendRequest {
    /// Recipient.
    pub recipient: ZecRecipient,
    /// Amount.
    pub amount: ZecAmount,
    /// Candidate UTXOs of the account address.
    pub utxos: Vec<ZecUtxo>,
    /// Outpoints spent by a journal record that may still confirm (never reused).
    pub reserved: Vec<ZecOutPoint>,
    /// Checked consensus fields of the next block.
    pub consensus: TxConsensus,
}

/// Why no plan was made (fixed texts).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZecPlanError {
    /// Zero, below the dust floor or above `MAX_MONEY`.
    AmountInvalid,
    /// Not enough confirmed funds for amount + fee.
    Insufficient {
        /// Confirmed spendable zatoshis.
        available: u64,
        /// Needed zatoshis (amount + fee).
        needed: u64,
    },
    /// More inputs than [`ZEC_MAX_INPUTS`] would be needed.
    TooManyInputs,
    /// The fee would exceed [`ZEC_FEE_ABS_CAP`].
    FeeTooHigh,
    /// No confirmed UTXO.
    NoFunds,
}

impl ZecPlanError {
    /// The fixed Korean text.
    #[must_use]
    pub fn text(self) -> String {
        match self {
            Self::AmountInvalid => format!(
                "보낼 금액이 올바르지 않습니다 (최소 {} ZEC).",
                format_zec(ZEC_DUST)
            ),
            Self::Insufficient { available, needed } => format!(
                "확인된 잔액이 부족합니다: 필요 {} (수수료 포함), 사용 가능 {}.",
                format_zec_and_zats(needed),
                format_zec_and_zats(available)
            ),
            Self::TooManyInputs => format!(
                "입력이 {ZEC_MAX_INPUTS}개를 넘어야 해서 한 번에 보낼 수 없습니다. 금액을 나눠 보내세요."
            ),
            Self::FeeTooHigh => "수수료가 상한을 넘습니다.".to_owned(),
            Self::NoFunds => "보낼 수 있는 확인된 잔액이 없습니다.".to_owned(),
        }
    }
}

impl fmt::Display for ZecPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text())
    }
}

impl std::error::Error for ZecPlanError {}

/// An approved-to-be plan: the unsigned transaction and everything the approval shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZecPlan {
    /// Spending account.
    pub account: ZecAccount,
    /// Recipient.
    pub recipient: ZecRecipient,
    /// Amount to the recipient (zatoshis).
    pub amount: u64,
    /// Fee (zatoshis, ZIP 317 plus any dust folded into it).
    pub fee: u64,
    /// The ZIP 317 conventional fee part of `fee`.
    pub conventional_fee: u64,
    /// Change back to our address (0 = no change output).
    pub change: u64,
    /// Selected inputs, in transaction order.
    pub inputs: Vec<ZecUtxo>,
    /// Consensus fields.
    pub consensus: TxConsensus,
    /// The unsigned transaction (empty scriptSigs).
    pub tx: ZecTx,
    /// Send-max request.
    pub send_max: bool,
}

impl ZecPlan {
    /// The spent outputs of every input (our `scriptPubKey`, the planned values), for ZIP 244.
    #[must_use]
    pub fn prevouts(&self) -> Vec<ZecPrevout> {
        let script = self.account.script_pubkey();
        self.inputs
            .iter()
            .map(|input| ZecPrevout {
                value: input.value,
                script_pubkey: script.clone(),
            })
            .collect()
    }

    /// Sum of the inputs.
    #[must_use]
    pub fn input_total(&self) -> u64 {
        self.inputs
            .iter()
            .map(|input| input.value)
            .fold(0_u64, u64::saturating_add)
    }

    /// The recipient is our own address.
    #[must_use]
    pub fn to_self(&self) -> bool {
        self.recipient.dest == self.account.dest()
    }

    /// The change output index (1) when there is change.
    #[must_use]
    pub const fn change_vout(&self) -> Option<u32> {
        if self.change > 0 { Some(1) } else { None }
    }
}

fn spk_len(dest: &ZecDest) -> usize {
    match dest {
        ZecDest::P2pkh(_) => 25,
        ZecDest::P2sh(_) => 23,
    }
}

/// Plans a send (spec/12 §7.2).
///
/// Eligible inputs: confirmed (`height` known), not coinbase, not reserved by an in-flight
/// record, our account's UTXOs, deduplicated. Selection is largest first (ties by outpoint), up to
/// [`ZEC_MAX_INPUTS`]. Change below [`ZEC_DUST`] is folded into the fee. A TEX recipient is always
/// P2PKH and a fully transparent transaction (ZIP 320).
///
/// # Errors
///
/// [`ZecPlanError`].
pub fn plan_send(account: &ZecAccount, request: &ZecSendRequest) -> Result<ZecPlan, ZecPlanError> {
    let mut eligible: Vec<ZecUtxo> = Vec::new();
    for utxo in &request.utxos {
        if utxo.height.is_none()
            || utxo.coinbase
            || utxo.value == 0
            || utxo.value > MAX_MONEY
            || request.reserved.contains(&utxo.outpoint)
            || eligible.iter().any(|known| known.outpoint == utxo.outpoint)
        {
            continue;
        }
        eligible.push(*utxo);
    }
    if eligible.is_empty() {
        return Err(ZecPlanError::NoFunds);
    }
    eligible.sort_by(|a, b| b.value.cmp(&a.value).then(a.outpoint.cmp(&b.outpoint)));
    let available = eligible
        .iter()
        .map(|utxo| utxo.value)
        .fold(0_u64, u64::saturating_add);
    let recipient_len = spk_len(&request.recipient.dest);
    let own_len = 25;
    let (inputs, amount, fee, conventional, change, send_max) = match request.amount {
        ZecAmount::Exact(amount) => {
            if !(ZEC_DUST..=MAX_MONEY).contains(&amount) {
                return Err(ZecPlanError::AmountInvalid);
            }
            select_exact(&eligible, amount, recipient_len, own_len, available)?
        }
        ZecAmount::Max => {
            let count = eligible.len();
            if count > ZEC_MAX_INPUTS {
                return Err(ZecPlanError::TooManyInputs);
            }
            let fee = planned_fee(count, &[recipient_len]);
            let amount = available.saturating_sub(fee);
            if amount < ZEC_DUST {
                return Err(ZecPlanError::Insufficient {
                    available,
                    needed: fee.saturating_add(ZEC_DUST),
                });
            }
            (eligible.clone(), amount, fee, fee, 0, true)
        }
    };
    if fee > ZEC_FEE_ABS_CAP {
        return Err(ZecPlanError::FeeTooHigh);
    }
    let mut outputs = vec![ZecTxOut {
        value: amount,
        script_pubkey: request.recipient.dest.script_pubkey(),
    }];
    if change > 0 {
        outputs.push(ZecTxOut {
            value: change,
            script_pubkey: account.script_pubkey(),
        });
    }
    let tx = ZecTx {
        branch_id: request.consensus.branch_id,
        lock_time: 0,
        expiry_height: request.consensus.expiry_height,
        inputs: inputs
            .iter()
            .map(|utxo| ZecTxIn {
                prevout: utxo.outpoint,
                script_sig: Vec::new(),
                sequence: ZEC_SEQUENCE,
            })
            .collect(),
        outputs,
    };
    Ok(ZecPlan {
        account: *account,
        recipient: request.recipient.clone(),
        amount,
        fee,
        conventional_fee: conventional,
        change,
        inputs,
        consensus: request.consensus,
        tx,
        send_max,
    })
}

type Selection = (Vec<ZecUtxo>, u64, u64, u64, u64, bool);

fn select_exact(
    eligible: &[ZecUtxo],
    amount: u64,
    recipient_len: usize,
    own_len: usize,
    available: u64,
) -> Result<Selection, ZecPlanError> {
    let mut chosen = Vec::new();
    let mut total = 0_u64;
    for utxo in eligible {
        if chosen.len() >= ZEC_MAX_INPUTS {
            return Err(ZecPlanError::TooManyInputs);
        }
        chosen.push(*utxo);
        total = total.saturating_add(utxo.value);
        let count = chosen.len();
        let fee_change = planned_fee(count, &[recipient_len, own_len]);
        if let Some(change) = total
            .checked_sub(amount)
            .and_then(|rest| rest.checked_sub(fee_change))
            && change >= ZEC_DUST
        {
            return Ok((chosen, amount, fee_change, fee_change, change, false));
        }
        let fee_plain = planned_fee(count, &[recipient_len]);
        if let Some(rest) = total
            .checked_sub(amount)
            .and_then(|rest| rest.checked_sub(fee_plain))
        {
            // No change output: the remainder (below the dust floor plus the change output's
            // own fee, since the branch above failed) goes to the fee.
            return Ok((
                chosen,
                amount,
                fee_plain.saturating_add(rest),
                fee_plain,
                0,
                false,
            ));
        }
    }
    let needed = amount.saturating_add(planned_fee(chosen.len().max(1), &[recipient_len]));
    Err(ZecPlanError::Insufficient { available, needed })
}
