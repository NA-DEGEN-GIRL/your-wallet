//! `eth_simulateV1`: request construction, result interpretation, asset diff and simulation
//! digest (spec/03 §1.3, §6, D15). New in v3.
//!
//! Simulation never blocks: every non-success becomes a high-risk warning (E01–E04, E07–E09, E36)
//! and a [`SimulationBinding`] for the approval digest. yw-app parses the RPC response with
//! yw-json into [`SimOutcome`] (yw-app `rpc::evm`); this module never sees raw network bytes.
#![deny(clippy::indexing_slicing)]

use core::fmt::Write as _;

use sha2::{Digest, Sha256};

use super::abi::{
    self, AbiType, AbiValue, TOPIC_APPROVAL, TOPIC_APPROVAL_FOR_ALL, TOPIC_PERMIT2_APPROVAL,
    TOPIC_PERMIT2_LOCKDOWN, TOPIC_TRANSFER, TOPIC_TRANSFER_BATCH, TOPIC_TRANSFER_SINGLE,
    TOPIC_WETH_DEPOSIT, TOPIC_WETH_WITHDRAWAL, address_word,
};
use super::address::Address;
use super::amount::{Delta, U256};
use super::chain::{ChainInfo, SimulationSupport};
use super::decode::revert_reason;
use super::risk::{self, E01, E02, E03, E04, E07, E08, E09, E36};
use super::tx::Eip1559Tx;
use crate::approval::{SimBinding, SimNoneReason, SimVerdict, SimulationBinding, Warning};
use crate::codec::transcript::{CodecError, Transcript};
use crate::hex::const_decode;

/// Synthetic native-transfer log emitter of `traceTransfers` before Glamsterdam (ERC-7528).
pub const ERC7528_NATIVE: Address = Address::from_bytes(const_decode::<20>(
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
));
/// Protocol native-transfer log emitter after Glamsterdam (EIP-7708).
pub const EIP7708_SYSTEM: Address = Address::from_bytes(const_decode::<20>(
    "fffffffffffffffffffffffffffffffffffffffe",
));
/// Maximum `eth_simulateV1` response size (spec/03 §1.4).
pub const MAX_SIM_RESPONSE_BYTES: usize = 4 * 1_024 * 1_024;
/// Maximum logs per simulated call (spec/03 §6.2).
pub const MAX_SIM_LOGS: usize = 1_024;
/// Maximum topics per log.
pub const MAX_LOG_TOPICS: usize = 4;
/// Maximum data bytes per log.
pub const MAX_LOG_DATA: usize = 65_536;
/// Maximum `returnData` bytes.
pub const MAX_RETURN_DATA: usize = 131_072;
/// Maximum displayed diff rows (sends + receives + approvals, E08).
pub const MAX_DIFF_ROWS: usize = 64;
/// Maximum |block time − now| before E07 (seconds).
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;
/// Transcript domain of the simulation digest (spec/03 §6.5).
pub const SIM_DIGEST_DOMAIN: &str = "your-wallet/v3/evm-simulation";
/// Transcript version of the simulation digest (2: the transaction signing hash is bound).
pub const SIM_DIGEST_VERSION: u16 = 2;

/// Status of the simulated call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimStatus {
    /// `status 0x1`.
    Success,
    /// `status 0x0`.
    Failure,
}

/// A simulated log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimLog {
    /// Emitter.
    pub address: Address,
    /// Topics (≤ 4).
    pub topics: Vec<[u8; 32]>,
    /// Data (≤ 65,536 bytes).
    pub data: Vec<u8>,
}

/// The call error object; `message` is discarded (never displayed, spec/03 §1.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimCallError {
    /// JSON-RPC style code (3 = revert).
    pub code: i64,
    /// Revert data.
    pub data: Option<Vec<u8>>,
}

/// The single simulated call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimCall {
    /// Status.
    pub status: SimStatus,
    /// Gas used.
    pub gas_used: u64,
    /// Peak gas (`maxUsedGas`, optional).
    pub max_used_gas: Option<u64>,
    /// Return data.
    pub return_data: Vec<u8>,
    /// Logs (empty when the call failed).
    pub logs: Vec<SimLog>,
    /// Error object.
    pub error: Option<SimCallError>,
}

/// The single simulated block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimBlock {
    /// Block number.
    pub number: u64,
    /// Parent hash.
    pub parent_hash: [u8; 32],
    /// Timestamp (unix seconds).
    pub timestamp: u64,
    /// Base fee.
    pub base_fee_per_gas: U256,
    /// The call.
    pub call: SimCall,
}

/// Transport failure kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportKind {
    /// No response within 10 s (or the preparation budget ran out).
    Timeout,
    /// HTTP 429 or JSON-RPC code 429.
    RateLimited,
    /// Any other transport failure.
    Other,
}

/// What yw-app observed for one `eth_simulateV1` attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SimOutcome {
    /// A well-formed block.
    Block(SimBlock),
    /// A top-level JSON-RPC error.
    RpcError {
        /// Error code.
        code: i64,
    },
    /// Transport failure.
    Transport(TransportKind),
    /// Shape or grammar violation.
    Malformed,
    /// Response or log limits exceeded.
    TooLarge,
    /// The chain is `simulation = unsupported`; no call was made.
    Unsupported,
}

/// Asset identifier of a diff row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AssetId {
    /// The chain's native asset.
    Native,
    /// A token contract (ERC-20/721/1155).
    Token(Address),
}

/// Whether a diff asset is verified: the native asset or a registry token (not an NFT id). Any
/// contract can emit a Transfer log naming the user, so only verified assets count as received
/// (E23/E40), lead the row order and are shown without "(미확인)" (spec/03 §6.4).
#[must_use]
pub fn is_verified_asset(chain: &ChainInfo, asset: &AssetId, token_id: Option<&U256>) -> bool {
    match asset {
        AssetId::Native => true,
        AssetId::Token(token) => token_id.is_none() && chain.token(token).is_some(),
    }
}

/// Net change of one asset for the signing account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetChange {
    /// Asset.
    pub asset: AssetId,
    /// ERC-721/1155 token id.
    pub token_id: Option<U256>,
    /// Net delta; `None` = the sum overflowed (`합산 불가`, E09).
    pub delta: Option<Delta>,
}

/// Approval change kinds (spec/03 §6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalKindEvm {
    /// ERC-20 allowance.
    Erc20 {
        /// New allowance.
        amount: U256,
    },
    /// ERC-721 single-token approval.
    Erc721 {
        /// Token id.
        token_id: U256,
        /// `approved == 0`.
        revoked: bool,
    },
    /// `ApprovalForAll`.
    ForAll {
        /// Granted or revoked.
        approved: bool,
    },
    /// Permit2 allowance.
    Permit2 {
        /// Amount (uint160).
        amount: U256,
        /// Expiration (uint48).
        expiration: u64,
    },
    /// Permit2 lockdown (revocation).
    Permit2Lockdown,
}

/// One approval change (last log per key wins).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalChange {
    /// Token.
    pub asset: Address,
    /// Spender / operator / approved address.
    pub spender: Address,
    /// Kind.
    pub kind: ApprovalKindEvm,
}

/// A transfer the signing account takes part in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferRow {
    /// Asset.
    pub asset: AssetId,
    /// Token id for NFTs.
    pub token_id: Option<U256>,
    /// Sender.
    pub from: Address,
    /// Receiver.
    pub to: Address,
    /// Amount (1 for ERC-721).
    pub amount: U256,
}

/// A classified log (spec/03 §6.4), independent of the signing account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogEvent {
    /// Selected native-transfer log (§1.3).
    Native {
        /// Sender.
        from: Address,
        /// Receiver.
        to: Address,
        /// Amount.
        amount: U256,
    },
    /// ERC-20 `Transfer`.
    Erc20Transfer {
        /// Emitter.
        token: Address,
        /// Sender.
        from: Address,
        /// Receiver.
        to: Address,
        /// Amount.
        amount: U256,
    },
    /// ERC-721 `Transfer`.
    Erc721Transfer {
        /// Emitter.
        token: Address,
        /// Sender.
        from: Address,
        /// Receiver.
        to: Address,
        /// Token id.
        id: U256,
    },
    /// ERC-1155 `TransferSingle` (batches are expanded).
    Erc1155Transfer {
        /// Emitter.
        token: Address,
        /// Sender.
        from: Address,
        /// Receiver.
        to: Address,
        /// `(id, value)` pairs.
        items: Vec<(U256, U256)>,
    },
    /// Registry WETH `Deposit`.
    WethDeposit {
        /// Emitter (registry WETH).
        token: Address,
        /// Receiver.
        dst: Address,
        /// Amount.
        wad: U256,
    },
    /// Registry WETH `Withdrawal`.
    WethWithdrawal {
        /// Emitter.
        token: Address,
        /// Sender.
        src: Address,
        /// Amount.
        wad: U256,
    },
    /// ERC-20 `Approval`.
    Erc20Approval {
        /// Emitter.
        token: Address,
        /// Owner.
        owner: Address,
        /// Spender.
        spender: Address,
        /// Allowance.
        amount: U256,
    },
    /// ERC-721 `Approval`.
    Erc721Approval {
        /// Emitter.
        token: Address,
        /// Owner.
        owner: Address,
        /// Approved address (0 = revoked).
        approved: Address,
        /// Token id.
        id: U256,
    },
    /// `ApprovalForAll`.
    ApprovalForAll {
        /// Emitter.
        token: Address,
        /// Owner.
        owner: Address,
        /// Operator.
        operator: Address,
        /// Granted.
        approved: bool,
    },
    /// Registry Permit2 `Approval`.
    Permit2Approval {
        /// Owner.
        owner: Address,
        /// Token.
        token: Address,
        /// Spender.
        spender: Address,
        /// Amount (uint160).
        amount: U256,
        /// Expiration (uint48).
        expiration: u64,
    },
    /// Registry Permit2 `Lockdown`.
    Permit2Lockdown {
        /// Owner.
        owner: Address,
        /// Token.
        token: Address,
        /// Spender.
        spender: Address,
    },
    /// Anything else or a shape mismatch.
    Other,
}

/// The interpreted effects of a simulated transaction (spec/03 §6.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationDiff {
    /// Block binding (number, parent hash, timestamp, base fee, digest).
    pub block: SimBinding,
    /// Net asset changes: verified assets ([`is_verified_asset`]) first, then the rest; within
    /// each group sends (and overflowed rows) first, then receipts.
    pub changes: Vec<AssetChange>,
    /// Approval changes.
    pub approvals: Vec<ApprovalChange>,
    /// Transfers involving the signing account (a WETH `Withdrawal` is a balance change only).
    pub transfers: Vec<TransferRow>,
    /// Logs classified as "기타" (E32).
    pub other_events: u32,
    /// Gas used.
    pub gas_used: u64,
    /// All classified logs in order (R4/R6 inputs). Empty when reverted.
    pub events: Vec<LogEvent>,
    /// Rows omitted beyond [`MAX_DIFF_ROWS`] (E08).
    pub omitted_rows: u32,
    /// The selected native emitter differs from the fork expectation (§1.3-3): log only.
    pub native_emitter_mismatch: bool,
}

/// Simulation verdict and warnings (spec/03 §6.2). Never contains a blocking warning.
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "built once per approval request; shape fixed by spec/03 §6.2"
)]
pub enum SimResult {
    /// A block was returned; `Reverted` has an empty diff.
    Simulated {
        /// Verdict.
        verdict: SimVerdict,
        /// Diff.
        diff: SimulationDiff,
        /// E02–E04, E07–E09.
        warnings: Vec<Warning>,
    },
    /// No result.
    Unavailable {
        /// Reason.
        reason: SimNoneReason,
        /// E01 or E36; `None` for `Skipped`.
        warning: Option<Warning>,
    },
}

impl SimResult {
    /// The approval-digest binding (spec/03 §11.1).
    #[must_use]
    pub fn binding(&self) -> SimulationBinding {
        match self {
            Self::Simulated { verdict, diff, .. } => SimulationBinding::Simulated {
                verdict: *verdict,
                block: diff.block,
            },
            Self::Unavailable { reason, .. } => SimulationBinding::None { reason: *reason },
        }
    }

    /// Simulation logs usable for R4/R6 (verdict `Ok` or `Incomplete`).
    #[must_use]
    pub fn events(&self) -> Option<&[LogEvent]> {
        match self {
            Self::Simulated {
                verdict: SimVerdict::Ok | SimVerdict::Incomplete,
                diff,
                ..
            } => Some(&diff.events),
            _ => None,
        }
    }

    /// The diff when logs are usable.
    #[must_use]
    pub fn diff(&self) -> Option<&SimulationDiff> {
        match self {
            Self::Simulated {
                verdict: SimVerdict::Ok | SimVerdict::Incomplete,
                diff,
                ..
            } => Some(diff),
            _ => None,
        }
    }

    /// All warnings of this result.
    #[must_use]
    pub fn warnings(&self) -> Vec<Warning> {
        match self {
            Self::Simulated { warnings, .. } => warnings.clone(),
            Self::Unavailable { warning, .. } => warning.iter().cloned().collect(),
        }
    }

    /// The "skipped because blocked" result (spec/03 §3.7).
    #[must_use]
    pub const fn skipped() -> Self {
        Self::Unavailable {
            reason: SimNoneReason::Skipped,
            warning: None,
        }
    }
}

fn quantity_u64(value: u64) -> String {
    U256::from_u64(value).to_quantity()
}

fn hex_data(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2).saturating_add(2));
    out.push_str("0x");
    crate::hex::encode_into(bytes, &mut out);
    out
}

/// The `eth_simulateV1` request for exactly the transaction to sign (spec/03 §6.1): fixed key
/// order, canonical quantities, lowercase hex, no overrides. `chain_and_type` follows §1.5 A3.
#[must_use]
pub fn simulate_request(id: u64, tx: &Eip1559Tx, from: &Address, chain_and_type: bool) -> Vec<u8> {
    let mut call = format!(
        "{{\"from\":\"{}\",\"to\":\"{}\",\"value\":\"{}\",\"input\":\"{}\",\"nonce\":\"{}\",\"gas\":\"{}\",\"maxFeePerGas\":\"{}\",\"maxPriorityFeePerGas\":\"{}\"",
        from.to_lower_hex(),
        tx.to.to_lower_hex(),
        tx.value.to_quantity(),
        hex_data(&tx.data),
        quantity_u64(tx.nonce),
        quantity_u64(tx.gas_limit),
        tx.max_fee_per_gas.to_quantity(),
        tx.max_priority_fee_per_gas.to_quantity(),
    );
    if chain_and_type {
        let _ = write!(
            call,
            ",\"chainId\":\"{}\",\"type\":\"0x2\"",
            quantity_u64(tx.chain_id)
        );
    }
    if !tx.access_list.is_empty() {
        call.push_str(",\"accessList\":[");
        for (index, item) in tx.access_list.iter().enumerate() {
            if index != 0 {
                call.push(',');
            }
            let _ = write!(
                call,
                "{{\"address\":\"{}\",\"storageKeys\":[",
                item.address.to_lower_hex()
            );
            for (key_index, key) in item.storage_keys.iter().enumerate() {
                if key_index != 0 {
                    call.push(',');
                }
                call.push('"');
                call.push_str(&hex_data(key));
                call.push('"');
            }
            call.push_str("]}");
        }
        call.push(']');
    }
    call.push('}');
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"eth_simulateV1\",\"params\":[{{\"blockStateCalls\":[{{\"calls\":[{call}]}}],\"traceTransfers\":true,\"validation\":true}},\"latest\"]}}"
    )
    .into_bytes()
}

/// `sim_digest` of a block simulated for `tx` (spec/03 §6.5, transcript version 2): the
/// transaction's signing hash first, so a result can never be bound to another transaction.
///
/// # Errors
///
/// [`CodecError::LengthOverflow`] for fields longer than `u32::MAX` (impossible within limits).
pub fn sim_digest(tx: &Eip1559Tx, block: &SimBlock) -> Result<[u8; 32], CodecError> {
    let call = &block.call;
    let mut transcript = Transcript::start_domain(SIM_DIGEST_DOMAIN, SIM_DIGEST_VERSION)?;
    transcript.push_bytes(&tx.signing_hash())?;
    transcript.push_u64(block.number);
    transcript.push_bytes(&block.parent_hash)?;
    transcript.push_u64(block.timestamp);
    transcript.push_bytes(block.base_fee_per_gas.as_be_bytes())?;
    transcript.push_u8(u8::from(call.status == SimStatus::Success));
    transcript.push_u64(call.gas_used);
    transcript.push_optional(call.max_used_gas.as_ref())?;
    transcript.push_bytes(&call.return_data)?;
    let count = u32::try_from(call.logs.len()).map_err(|_| CodecError::LengthOverflow)?;
    transcript.push_u32(count);
    for log in &call.logs {
        transcript.push_bytes(log.address.as_bytes())?;
        let topics = u8::try_from(log.topics.len()).map_err(|_| CodecError::LengthOverflow)?;
        transcript.push_u8(topics);
        for topic in &log.topics {
            transcript.push_bytes(topic)?;
        }
        transcript.push_bytes(&log.data)?;
    }
    Ok(Sha256::digest(transcript.as_bytes()).into())
}

fn none(reason: SimNoneReason, cause: &str) -> SimResult {
    SimResult::Unavailable {
        reason,
        warning: Some(risk::warning(E01, Some(cause))),
    }
}

fn rpc_error_cause(code: i64) -> String {
    match code {
        -32_601 => "RPC가 eth_simulateV1을 지원하지 않습니다(체인 설정에서 시뮬레이션을 \"미지원\"으로 바꿀 수 있습니다)".to_owned(),
        -38_010 => "nonce가 이미 사용되었습니다. 다른 곳에서 이 계정으로 거래가 전송되었을 수 있습니다".to_owned(),
        -38_011 => "앞선 거래가 아직 처리되지 않았습니다".to_owned(),
        -38_012 | -32_005 => "최대 수수료가 현재 기본 수수료보다 낮습니다".to_owned(),
        -38_013 => "가스 한도가 최소 필요량보다 작습니다".to_owned(),
        -38_014 | -32_003 => "잔액이 보낼 금액과 최대 수수료의 합보다 적습니다".to_owned(),
        -38_015 => "가스 한도가 블록 가스 한도를 넘습니다".to_owned(),
        other => format!("시뮬레이션 노드 오류(코드 {other})"),
    }
}

fn unavailable(outcome: &SimOutcome) -> Option<SimResult> {
    Some(match outcome {
        SimOutcome::Block(_) => return None,
        SimOutcome::Unsupported => SimResult::Unavailable {
            reason: SimNoneReason::Unsupported,
            warning: Some(risk::warning(E36, None)),
        },
        SimOutcome::Transport(TransportKind::Timeout) => {
            none(SimNoneReason::Timeout, "시뮬레이션 응답이 없습니다(10초)")
        }
        SimOutcome::Transport(TransportKind::RateLimited) | SimOutcome::RpcError { code: 429 } => {
            none(SimNoneReason::RateLimited, "RPC 요청 한도를 넘었습니다")
        }
        SimOutcome::Transport(TransportKind::Other) => none(
            SimNoneReason::Transport,
            "시뮬레이션 RPC에 연결할 수 없습니다",
        ),
        SimOutcome::TooLarge => none(SimNoneReason::TooLarge, "시뮬레이션 응답이 너무 큽니다"),
        SimOutcome::Malformed => malformed(),
        SimOutcome::RpcError { code } => none(SimNoneReason::RpcError, &rpc_error_cause(*code)),
    })
}

fn malformed() -> SimResult {
    none(
        SimNoneReason::Malformed,
        "시뮬레이션 응답 형식이 올바르지 않습니다",
    )
}

fn topic_address(log: &SimLog, index: usize) -> Option<Address> {
    address_word(log.topics.get(index)?)
}

fn data_word(log: &SimLog, index: usize) -> Option<&[u8; 32]> {
    let start = index.checked_mul(32)?;
    log.data.get(start..start.checked_add(32)?)?.try_into().ok()
}

/// A native log (§1.3-1 shape), `Err` when the shape is wrong.
fn native_log(log: &SimLog) -> Result<(Address, Address, U256), ()> {
    if log.topics.len() != 3 || log.topics.first() != Some(&TOPIC_TRANSFER) || log.data.len() != 32
    {
        return Err(());
    }
    let from = topic_address(log, 1).ok_or(())?;
    let to = topic_address(log, 2).ok_or(())?;
    let amount = U256::from_be_bytes(*data_word(log, 0).ok_or(())?);
    Ok((from, to, amount))
}

fn classify(chain: &ChainInfo, log: &SimLog) -> LogEvent {
    classify_inner(chain, log).unwrap_or(LogEvent::Other)
}

#[expect(
    clippy::too_many_lines,
    reason = "one arm per row of the spec/03 §6.4 table"
)]
fn classify_inner(chain: &ChainInfo, log: &SimLog) -> Option<LogEvent> {
    let first_topic = log.topics.first()?;
    let emitter = log.address;
    let topics = log.topics.len();
    let data = log.data.len();
    let event = match *first_topic {
        TOPIC_TRANSFER if topics == 3 && data == 32 => LogEvent::Erc20Transfer {
            token: emitter,
            from: topic_address(log, 1)?,
            to: topic_address(log, 2)?,
            amount: U256::from_be_bytes(*data_word(log, 0)?),
        },
        TOPIC_TRANSFER if topics == 4 && data == 0 => LogEvent::Erc721Transfer {
            token: emitter,
            from: topic_address(log, 1)?,
            to: topic_address(log, 2)?,
            id: U256::from_be_bytes(*log.topics.get(3)?),
        },
        TOPIC_TRANSFER_SINGLE if topics == 4 && data == 64 => {
            topic_address(log, 1)?;
            LogEvent::Erc1155Transfer {
                token: emitter,
                from: topic_address(log, 2)?,
                to: topic_address(log, 3)?,
                items: vec![(
                    U256::from_be_bytes(*data_word(log, 0)?),
                    U256::from_be_bytes(*data_word(log, 1)?),
                )],
            }
        }
        TOPIC_TRANSFER_BATCH if topics == 4 => {
            topic_address(log, 1)?;
            let values = abi::decode_params(&[AbiType::UintArray, AbiType::UintArray], &log.data)?;
            let (Some(AbiValue::Array(ids)), Some(AbiValue::Array(amounts))) =
                (values.first(), values.get(1))
            else {
                return None;
            };
            if ids.len() != amounts.len() {
                return None;
            }
            let items = ids
                .iter()
                .zip(amounts)
                .map(|pair| match pair {
                    (AbiValue::Uint(id), AbiValue::Uint(amount)) => Some((*id, *amount)),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()?;
            LogEvent::Erc1155Transfer {
                token: emitter,
                from: topic_address(log, 2)?,
                to: topic_address(log, 3)?,
                items,
            }
        }
        TOPIC_WETH_DEPOSIT if chain.is_weth(&emitter) && topics == 2 && data == 32 => {
            LogEvent::WethDeposit {
                token: emitter,
                dst: topic_address(log, 1)?,
                wad: U256::from_be_bytes(*data_word(log, 0)?),
            }
        }
        TOPIC_WETH_WITHDRAWAL if chain.is_weth(&emitter) && topics == 2 && data == 32 => {
            LogEvent::WethWithdrawal {
                token: emitter,
                src: topic_address(log, 1)?,
                wad: U256::from_be_bytes(*data_word(log, 0)?),
            }
        }
        TOPIC_APPROVAL if topics == 3 && data == 32 => LogEvent::Erc20Approval {
            token: emitter,
            owner: topic_address(log, 1)?,
            spender: topic_address(log, 2)?,
            amount: U256::from_be_bytes(*data_word(log, 0)?),
        },
        TOPIC_APPROVAL if topics == 4 && data == 0 => LogEvent::Erc721Approval {
            token: emitter,
            owner: topic_address(log, 1)?,
            approved: topic_address(log, 2)?,
            id: U256::from_be_bytes(*log.topics.get(3)?),
        },
        TOPIC_APPROVAL_FOR_ALL if topics == 3 && data == 32 => {
            let flag = U256::from_be_bytes(*data_word(log, 0)?);
            let approved = match flag.to_u64() {
                Some(0) => false,
                Some(1) => true,
                _ => return None,
            };
            LogEvent::ApprovalForAll {
                token: emitter,
                owner: topic_address(log, 1)?,
                operator: topic_address(log, 2)?,
                approved,
            }
        }
        TOPIC_PERMIT2_APPROVAL if chain.is_permit2(&emitter) && topics == 4 && data == 64 => {
            let amount = U256::from_be_bytes(*data_word(log, 0)?);
            let expiration = U256::from_be_bytes(*data_word(log, 1)?);
            if !amount.fits_bits(160) || !expiration.fits_bits(48) {
                return None;
            }
            LogEvent::Permit2Approval {
                owner: topic_address(log, 1)?,
                token: topic_address(log, 2)?,
                spender: topic_address(log, 3)?,
                amount,
                expiration: expiration.to_u64()?,
            }
        }
        TOPIC_PERMIT2_LOCKDOWN if chain.is_permit2(&emitter) && topics == 2 && data == 64 => {
            LogEvent::Permit2Lockdown {
                owner: topic_address(log, 1)?,
                token: address_word(data_word(log, 0)?)?,
                spender: address_word(data_word(log, 1)?)?,
            }
        }
        _ => return None,
    };
    Some(event)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ApprovalClass {
    Erc20,
    Erc721,
    ForAll,
    Permit2,
}

/// Asset key: asset and NFT id.
type AssetKey = (AssetId, Option<U256>);
/// Per-asset sums: (key, received, sent); `None` = overflowed.
type AssetSums = (AssetKey, Option<U256>, Option<U256>);
/// Approval key: class, token, spender, NFT id.
type ApprovalKey = (ApprovalClass, Address, Address, Option<U256>);

struct DiffBuilder {
    user: Address,
    sums: Vec<AssetSums>,
    approvals: Vec<(ApprovalKey, ApprovalChange)>,
    transfers: Vec<TransferRow>,
    other_events: u32,
}

impl DiffBuilder {
    fn add_sum(&mut self, key: AssetKey, amount: U256, incoming: bool) {
        let index = if let Some(index) = self
            .sums
            .iter()
            .position(|(existing, _, _)| *existing == key)
        {
            index
        } else {
            self.sums.push((key, Some(U256::ZERO), Some(U256::ZERO)));
            self.sums.len().saturating_sub(1)
        };
        if let Some((_, received, sent)) = self.sums.get_mut(index) {
            let slot = if incoming { received } else { sent };
            *slot = slot.and_then(|value| value.checked_add(amount));
        }
    }

    fn transfer(
        &mut self,
        asset: AssetId,
        token_id: Option<U256>,
        from: Address,
        to: Address,
        amount: U256,
    ) {
        if from != self.user && to != self.user {
            self.other();
            return;
        }
        if from == self.user {
            self.add_sum((asset, token_id), amount, false);
        }
        if to == self.user {
            self.add_sum((asset, token_id), amount, true);
        }
        self.transfers.push(TransferRow {
            asset,
            token_id,
            from,
            to,
            amount,
        });
    }

    fn approval(
        &mut self,
        class: ApprovalClass,
        owner: Address,
        key_spender: Address,
        key_id: Option<U256>,
        change: ApprovalChange,
    ) {
        if owner != self.user {
            self.other();
            return;
        }
        let key = (class, change.asset, key_spender, key_id);
        if let Some((_, existing)) = self.approvals.iter_mut().find(|(k, _)| *k == key) {
            *existing = change;
        } else {
            self.approvals.push((key, change));
        }
    }

    fn other(&mut self) {
        self.other_events = self.other_events.saturating_add(1);
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one arm per log class of spec/03 §6.4"
    )]
    fn apply(&mut self, event: &LogEvent) {
        match event {
            LogEvent::Native { from, to, amount } => {
                self.transfer(AssetId::Native, None, *from, *to, *amount);
            }
            LogEvent::Erc20Transfer {
                token,
                from,
                to,
                amount,
            } => self.transfer(AssetId::Token(*token), None, *from, *to, *amount),
            LogEvent::Erc721Transfer {
                token,
                from,
                to,
                id,
            } => self.transfer(AssetId::Token(*token), Some(*id), *from, *to, U256::ONE),
            LogEvent::Erc1155Transfer {
                token,
                from,
                to,
                items,
            } => {
                if *from != self.user && *to != self.user {
                    self.other();
                    return;
                }
                for (id, value) in items {
                    self.transfer(AssetId::Token(*token), Some(*id), *from, *to, *value);
                }
            }
            LogEvent::WethDeposit { token, dst, wad } => {
                if *dst == self.user {
                    self.transfer(AssetId::Token(*token), None, *token, *dst, *wad);
                } else {
                    self.other();
                }
            }
            LogEvent::WethWithdrawal { token, src, wad } => {
                // An unwrap burns the wrapped token: it changes the balance but is not a
                // transfer to the token contract (no E18 row, spec/03 §6.4).
                if *src == self.user {
                    self.add_sum((AssetId::Token(*token), None), *wad, false);
                } else {
                    self.other();
                }
            }
            LogEvent::Erc20Approval {
                token,
                owner,
                spender,
                amount,
            } => self.approval(
                ApprovalClass::Erc20,
                *owner,
                *spender,
                None,
                ApprovalChange {
                    asset: *token,
                    spender: *spender,
                    kind: ApprovalKindEvm::Erc20 { amount: *amount },
                },
            ),
            LogEvent::Erc721Approval {
                token,
                owner,
                approved,
                id,
            } => self.approval(
                ApprovalClass::Erc721,
                *owner,
                Address::from_bytes([0; 20]),
                Some(*id),
                ApprovalChange {
                    asset: *token,
                    spender: *approved,
                    kind: ApprovalKindEvm::Erc721 {
                        token_id: *id,
                        revoked: approved.as_bytes() == &[0; 20],
                    },
                },
            ),
            LogEvent::ApprovalForAll {
                token,
                owner,
                operator,
                approved,
            } => self.approval(
                ApprovalClass::ForAll,
                *owner,
                *operator,
                None,
                ApprovalChange {
                    asset: *token,
                    spender: *operator,
                    kind: ApprovalKindEvm::ForAll {
                        approved: *approved,
                    },
                },
            ),
            LogEvent::Permit2Approval {
                owner,
                token,
                spender,
                amount,
                expiration,
            } => self.approval(
                ApprovalClass::Permit2,
                *owner,
                *spender,
                None,
                ApprovalChange {
                    asset: *token,
                    spender: *spender,
                    kind: ApprovalKindEvm::Permit2 {
                        amount: *amount,
                        expiration: *expiration,
                    },
                },
            ),
            LogEvent::Permit2Lockdown {
                owner,
                token,
                spender,
            } => self.approval(
                ApprovalClass::Permit2,
                *owner,
                *spender,
                None,
                ApprovalChange {
                    asset: *token,
                    spender: *spender,
                    kind: ApprovalKindEvm::Permit2Lockdown,
                },
            ),
            LogEvent::Other => self.other(),
        }
    }
}

/// Interprets one simulation outcome for the transaction about to be signed (spec/03 §6.2–§6.4).
/// Never produces a blocking warning (D15).
#[must_use]
pub fn interpret(
    chain: &ChainInfo,
    tx: &Eip1559Tx,
    from: &Address,
    outcome: &SimOutcome,
    now_unix_ms: u64,
) -> SimResult {
    if chain.simulation == SimulationSupport::Unsupported {
        return unavailable(&SimOutcome::Unsupported).unwrap_or_else(malformed);
    }
    if let Some(result) = unavailable(outcome) {
        return result;
    }
    let SimOutcome::Block(block) = outcome else {
        return malformed();
    };
    interpret_block(chain, tx, from, block, now_unix_ms)
}

#[expect(clippy::too_many_lines, reason = "linear spec/03 §6.3–§6.4 evaluation")]
fn interpret_block(
    chain: &ChainInfo,
    tx: &Eip1559Tx,
    user: &Address,
    block: &SimBlock,
    now_unix_ms: u64,
) -> SimResult {
    let call = &block.call;
    if call.logs.len() > MAX_SIM_LOGS
        || call.return_data.len() > MAX_RETURN_DATA
        || call
            .logs
            .iter()
            .any(|log| log.topics.len() > MAX_LOG_TOPICS || log.data.len() > MAX_LOG_DATA)
    {
        return none(SimNoneReason::TooLarge, "시뮬레이션 응답이 너무 큽니다");
    }
    let Ok(digest) = sim_digest(tx, block) else {
        return none(SimNoneReason::TooLarge, "시뮬레이션 응답이 너무 큽니다");
    };
    let binding = SimBinding {
        number: block.number,
        parent_hash: block.parent_hash,
        timestamp: block.timestamp,
        base_fee: block.base_fee_per_gas,
        sim_digest: digest,
    };
    let mut diff = SimulationDiff {
        block: binding,
        changes: Vec::new(),
        approvals: Vec::new(),
        transfers: Vec::new(),
        other_events: 0,
        gas_used: call.gas_used,
        events: Vec::new(),
        omitted_rows: 0,
        native_emitter_mismatch: false,
    };
    if call.status == SimStatus::Failure {
        let cause = match &call.error {
            Some(SimCallError { code: 3, data }) => {
                format!("이유: {}", revert_reason(data.as_deref().unwrap_or(&[])))
            }
            Some(SimCallError { code, .. }) => {
                format!("이유: 실행 오류(가스 부족 등, 코드 {code})")
            }
            None => format!("이유: {}", revert_reason(&call.return_data)),
        };
        return SimResult::Simulated {
            verdict: SimVerdict::Reverted,
            diff,
            warnings: vec![risk::warning(E02, Some(&cause))],
        };
    }

    // §1.3: native log shape, emitter selection, fork expectation.
    let mut system = Vec::new();
    let mut synthetic = Vec::new();
    for (index, log) in call.logs.iter().enumerate() {
        if log.address == EIP7708_SYSTEM || log.address == ERC7528_NATIVE {
            let Ok(parsed) = native_log(log) else {
                return malformed();
            };
            if log.address == EIP7708_SYSTEM {
                system.push((index, parsed));
            } else {
                synthetic.push((index, parsed));
            }
        }
    }
    let (selected, selected_emitter) = if system.is_empty() {
        (synthetic, ERC7528_NATIVE)
    } else {
        (system, EIP7708_SYSTEM)
    };
    let expected = if chain
        .amsterdam_time
        .is_some_and(|activation| block.timestamp >= activation)
    {
        EIP7708_SYSTEM
    } else {
        ERC7528_NATIVE
    };
    diff.native_emitter_mismatch = !selected.is_empty() && selected_emitter != expected;

    let mut warnings = Vec::new();
    let mut builder = DiffBuilder {
        user: *user,
        sums: Vec::new(),
        approvals: Vec::new(),
        transfers: Vec::new(),
        other_events: 0,
    };
    for (index, log) in call.logs.iter().enumerate() {
        let event = if log.address == EIP7708_SYSTEM || log.address == ERC7528_NATIVE {
            match selected.iter().find(|(position, _)| *position == index) {
                Some((_, (from, to, amount))) => LogEvent::Native {
                    from: *from,
                    to: *to,
                    amount: *amount,
                },
                None => continue,
            }
        } else {
            classify(chain, log)
        };
        builder.apply(&event);
        diff.events.push(event);
    }

    // E03
    if call.gas_used > tx.gas_limit || call.max_used_gas.is_some_and(|peak| peak > tx.gas_limit) {
        warnings.push(risk::warning(E03, Some("사용 가스가 가스 한도를 넘습니다")));
    }
    // E04 (self-transfers are skipped: EIP-7708 chains emit no log for them).
    if !tx.value.is_zero() && tx.to != *user {
        let confirmed = selected
            .iter()
            .any(|(_, (from, to, amount))| from == user && *to == tx.to && *amount == tx.value);
        if !confirmed {
            let cause = format!("{} 이동이 확인되지 않습니다", chain.native_symbol);
            warnings.push(risk::warning(E04, Some(&cause)));
        }
    }
    // E07
    let now_secs = now_unix_ms / 1_000;
    let skew = now_secs.abs_diff(block.timestamp);
    if skew > MAX_CLOCK_SKEW_SECS {
        let cause = format!("기준 블록 시각이 현재와 {skew}초 다릅니다");
        warnings.push(risk::warning(E07, Some(&cause)));
    }

    // Asset rows (spec/03 §6.4): native and registered tokens first (sends, then receipts), then
    // every other token and NFT (sends, then receipts); overflowed rows count as sends. Any
    // contract can emit Transfer logs naming the user, so unverified rows never push a verified
    // row past the display limit.
    let mut ranked: Vec<(u8, AssetChange)> = Vec::new();
    let mut overflow = false;
    for ((asset, token_id), received, sent) in &builder.sums {
        let delta = if let (Some(received), Some(sent)) = (received, sent) {
            match Delta::from_sums(*received, *sent) {
                Delta::Zero => continue,
                delta => Some(delta),
            }
        } else {
            overflow = true;
            None
        };
        let unverified = !is_verified_asset(chain, asset, token_id.as_ref());
        let incoming = matches!(delta, Some(Delta::In(_)));
        ranked.push((
            u8::from(unverified)
                .saturating_mul(2)
                .saturating_add(u8::from(incoming)),
            AssetChange {
                asset: *asset,
                token_id: *token_id,
                delta,
            },
        ));
    }
    ranked.sort_by_key(|(rank, _)| *rank);
    if overflow {
        warnings.push(risk::warning(E09, Some("금액 합산이 범위를 넘었습니다")));
    }
    let verified_rows = ranked.iter().filter(|(rank, _)| *rank < 2).count();
    let mut changes: Vec<AssetChange> = ranked.into_iter().map(|(_, change)| change).collect();
    let mut approvals: Vec<ApprovalChange> = builder
        .approvals
        .into_iter()
        .map(|(_, change)| change)
        .collect();
    let total = changes.len().saturating_add(approvals.len());
    if total > MAX_DIFF_ROWS {
        // Keep, in this order: verified asset rows, approvals of registered tokens, other
        // approvals, unverified asset rows.
        let omitted = total.saturating_sub(MAX_DIFF_ROWS);
        let mut budget = MAX_DIFF_ROWS;
        let keep_verified = verified_rows.min(budget);
        budget = budget.saturating_sub(keep_verified);
        let mut keep = vec![false; approvals.len()];
        for registered in [true, false] {
            for (slot, change) in keep.iter_mut().zip(&approvals) {
                if budget > 0 && !*slot && chain.token(&change.asset).is_some() == registered {
                    *slot = true;
                    budget = budget.saturating_sub(1);
                }
            }
        }
        let keep_unverified = changes.len().saturating_sub(verified_rows).min(budget);
        changes.truncate(keep_verified.saturating_add(keep_unverified));
        let mut flags = keep.into_iter();
        approvals.retain(|_| flags.next().unwrap_or(false));
        diff.omitted_rows = u32::try_from(omitted).unwrap_or(u32::MAX);
        let cause = format!("표시 한도를 넘어 {omitted}행을 생략했습니다");
        warnings.push(risk::warning(E08, Some(&cause)));
    }
    diff.changes = changes;
    diff.approvals = approvals;
    diff.transfers = builder.transfers;
    diff.other_events = builder.other_events;

    let verdict = if warnings.is_empty() {
        SimVerdict::Ok
    } else {
        SimVerdict::Incomplete
    };
    SimResult::Simulated {
        verdict,
        diff,
        warnings,
    }
}

/// Freshness window of a simulation result (D23, spec/03 §6.6).
pub const SIM_FRESHNESS_MS: u64 = 60_000;

/// Whether a click at `now_ms` must re-simulate first (spec/03 §6.6 1–3): only a `Simulated`
/// binding older than 60 s; a `None` binding (no result, unsupported) is consumed as is.
#[must_use]
pub fn needs_resimulation(binding: &SimulationBinding, received_ms: u64, now_ms: u64) -> bool {
    matches!(binding, SimulationBinding::Simulated { .. })
        && now_ms.saturating_sub(received_ms) > SIM_FRESHNESS_MS
}
