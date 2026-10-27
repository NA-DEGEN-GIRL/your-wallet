//! The SOL approval request (spec/07 §13.3): title, display fields `0x0001`–`0x0003` and
//! `0x0501`–`0x0509`, and the `L01`–`L08` warnings (`RuleId` family `'L'`, spec/03 §10.1).
//! Strings that come from the user (labels) are escaped; nothing from RPC is shown verbatim.

use core::fmt::Write as _;

use super::address::{SolCluster, grouped};
use super::broadcast::err;
use super::fee::{FeeError, SOL_BASE_FEE_LAMPORTS_PER_SIG, priority_fee};
use super::intent::{SolTransferIntent, flags};
use super::recipient::{AccountClass, KnownKind, RecipientCheck};
use super::rent::{RentError, format_amount, format_raw};
use super::template::{SolAsset, SolTransferCore};
use crate::approval::{
    AccountRef, ApprovalDisplay, ApprovalDraft, ApprovalId, ApprovalKind, ApprovalOrigin, ChainRef,
    DisplayError, DisplayField, FieldKey, MAX_TITLE_BYTES, RiskLevel, RuleId, Signer,
    SigningPayload, SimulationBinding, Warning, escape_edges, escape_untrusted,
};
use crate::slip10::SolKeySource;

/// `L01` approval impossible (blocked).
pub const L01: RuleId = RuleId::new(b'L', 1);
/// `L02` off-curve recipient (high).
pub const L02: RuleId = RuleId::new(b'L', 2);
/// `L03` lookalike recipient (high).
pub const L03: RuleId = RuleId::new(b'L', 3);
/// `L04` program-owned recipient account (high).
pub const L04: RuleId = RuleId::new(b'L', 4);
/// `L05` simulation failure / CU overrun (high).
pub const L05: RuleId = RuleId::new(b'L', 5);
/// `L06` first-time recipient (caution).
pub const L06: RuleId = RuleId::new(b'L', 6);
/// `L07` non-standard path account (caution).
pub const L07: RuleId = RuleId::new(b'L', 7);
/// `L08` send max (info).
pub const L08: RuleId = RuleId::new(b'L', 8);

/// The level of an `L` rule.
#[must_use]
pub fn level_of(rule: RuleId) -> Option<RiskLevel> {
    Some(match rule {
        r if r == L01 => RiskLevel::Blocked,
        r if r == L02 || r == L03 || r == L04 || r == L05 => RiskLevel::High,
        r if r == L06 || r == L07 => RiskLevel::Caution,
        r if r == L08 => RiskLevel::Info,
        _ => return None,
    })
}

/// Why the request cannot be approved (`L01`, spec/07 §13.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolBlock {
    /// `getGenesisHash` differs from the cluster.
    ClusterMismatch,
    /// Fee arithmetic, cap, or `getFeeForMessage` cross-check.
    Fee(FeeError),
    /// Rent or balance rule.
    Rent(RentError),
    /// The recipient is a token account or mint (§12.2).
    RecipientIsTokenAccount,
    /// The recipient is an executable program (§12.2).
    RecipientIsProgram,
    /// An implausible RPC value (`lastValidBlockHeight`, rent).
    RpcAnomaly,
    /// A `Pending` transfer of the same (cluster, account) exists.
    PendingExists,
    /// No room in the journal (`JournalError::Full`, E-TX-005).
    JournalFull,
}

impl SolBlock {
    /// Fixed reason text.
    #[must_use]
    pub fn text(self) -> String {
        match self {
            Self::ClusterMismatch => {
                "RPC가 다른 Solana 클러스터를 가리킵니다(제네시스 불일치)".to_owned()
            }
            Self::Fee(error) => error.to_string(),
            Self::Rent(error) => error.to_string(),
            Self::RecipientIsTokenAccount => {
                "지갑 주소가 아니라 토큰 계정/mint 주소입니다".to_owned()
            }
            Self::RecipientIsProgram => "받는 주소가 프로그램입니다".to_owned(),
            Self::RpcAnomaly => "RPC 응답 값이 비정상입니다".to_owned(),
            Self::PendingExists => "이 계정의 이전 전송을 확인 중입니다".to_owned(),
            Self::JournalFull => "거래 저널 공간이 부족합니다".to_owned(),
        }
    }
}

/// `simulateTransaction` summary (reference only, D27).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimSummary {
    /// `err: null` with `unitsConsumed`.
    Ok {
        /// `unitsConsumed`.
        units: u64,
    },
    /// `err` classified (spec/07 §15.3).
    Failed {
        /// Code.
        err: u16,
        /// `unitsConsumed` if reported.
        units: Option<u64>,
    },
    /// No usable result (transport, RPC error, malformed).
    NoResult,
}

impl SimSummary {
    /// Whether it raises `L05` (failure, or more units than the limit).
    #[must_use]
    pub fn warns(self, cu_limit: u32) -> bool {
        match self {
            Self::Ok { units } => units > u64::from(cu_limit),
            Self::Failed { .. } => true,
            Self::NoResult => false,
        }
    }
}

/// Step-2 preview facts that are shown but not signed (spec/07 §13.1-2, §13.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolPreviewFacts {
    /// Sender account label (meta).
    pub account_label: String,
    /// Recipient check (§12.1).
    pub recipient: RecipientCheck,
    /// `getAccountInfo(to)` classification (§12.2).
    pub recipient_account: AccountClass,
    /// `getBalance(from)`, finalized.
    pub balance: u64,
    /// `getMinimumBalanceForRentExemption(0)`.
    pub rent0: u64,
    /// `getFeeForMessage` of the preview message.
    pub rpc_fee: Option<u64>,
    /// Simulation (reference).
    pub simulation: SimSummary,
    /// `L01` reasons.
    pub blocks: Vec<SolBlock>,
}

/// The flags of an intent from what will be shown (spec/07 §13.2): every warning bit the
/// approval window displays.
#[must_use]
pub fn intent_flags(
    send_max: bool,
    recipient: &RecipientCheck,
    account: AccountClass,
    simulation: SimSummary,
    cu_limit: u32,
    source: SolKeySource,
) -> u8 {
    let mut out = 0_u8;
    if send_max {
        out |= flags::SEND_MAX;
    }
    if recipient.off_curve {
        out |= flags::OFF_CURVE;
    }
    if recipient.first_time {
        out |= flags::FIRST_TIME;
    }
    if !recipient.lookalikes.is_empty() {
        out |= flags::LOOKALIKE;
    }
    if account == AccountClass::ProgramOwned {
        out |= flags::PROGRAM_OWNED;
    }
    if simulation.warns(cu_limit) {
        out |= flags::SIM_WARNING;
    }
    if !source.is_standard() {
        out |= flags::NON_STANDARD_PATH;
    }
    out
}

fn escape_label(text: &str) -> String {
    let escaped = escape_untrusted(text).text.replace('\n', "[U+000A]");
    let value = escape_edges(&escaped);
    if value.is_empty() {
        "(이름 없음)".to_owned()
    } else {
        value
    }
}

/// `1.000000000 SOL` + newline + `1,000,000,000 lamports`.
#[must_use]
pub fn lamports_text(lamports: u64) -> String {
    format!(
        "{} SOL\n{} lamports",
        format_amount(lamports, 9),
        format_raw(lamports)
    )
}

/// The approval title of a transfer (`[Solana devnet (테스트)] SOL 전송: 1.000000000 SOL`). The
/// journal activity rebuilds the same string from the transaction bytes (spec/07 §14.1).
#[must_use]
pub fn transfer_title(cluster: SolCluster, core: &SolTransferCore) -> String {
    let title = match core.asset {
        SolAsset::Sol => format!(
            "[{}] SOL 전송: {} SOL",
            cluster.display_name(),
            format_amount(core.amount, 9)
        ),
    };
    if title.len() <= MAX_TITLE_BYTES {
        title
    } else {
        format!("[{}] SOL 전송", cluster.display_name())
    }
}

fn warning(rule: RuleId, text: String) -> Warning {
    Warning {
        rule,
        level: level_of(rule).unwrap_or(RiskLevel::High),
        text,
    }
}

fn lookalike_text(recipient: &RecipientCheck) -> String {
    let mut lines =
        vec!["앞 3자 또는 뒤 3자가 같은 다른 주소입니다 — 주소 오염 공격일 수 있습니다".to_owned()];
    for entry in &recipient.lookalikes {
        let name = escape_label(&entry.label);
        lines.push(match &entry.kind {
            KnownKind::Book { .. } => {
                format!("주소록 '{name}'과 비슷함: {}", grouped(&entry.address))
            }
            KnownKind::Own { .. } => {
                format!("내 계정 '{name}'과 비슷함: {}", grouped(&entry.address))
            }
            KnownKind::Sent => format!("보낸 내역의 주소와 비슷함: {}", grouped(&entry.address)),
        });
    }
    lines.join("\n")
}

fn sim_text(simulation: SimSummary, cu_limit: u32) -> String {
    match simulation {
        SimSummary::Ok { units } if units > u64::from(cu_limit) => {
            format!("CU 초과: 사용 {units} > 한도 {cu_limit}")
        }
        SimSummary::Ok { units } => format!("성공(CU {units})"),
        SimSummary::Failed { err: code, .. } => format!("실패: {}", err::text(code)),
        SimSummary::NoResult => "결과 없음(참고 정보이며 승인을 막지 않습니다)".to_owned(),
    }
}

fn warnings(intent: &SolTransferIntent, facts: &SolPreviewFacts) -> Vec<Warning> {
    let mut out: Vec<Warning> = facts
        .blocks
        .iter()
        .map(|block| warning(L01, format!("보낼 수 없습니다: {}", block.text())))
        .collect();
    if intent.has(flags::OFF_CURVE) {
        out.push(warning(
            L02,
            "일반 지갑이 아님: 프로그램 소유 주소(PDA)나 토큰 계정일 수 있음".to_owned(),
        ));
    }
    if intent.has(flags::LOOKALIKE) {
        out.push(warning(L03, lookalike_text(&facts.recipient)));
    }
    if intent.has(flags::PROGRAM_OWNED) {
        out.push(warning(
            L04,
            "받는 주소가 프로그램 소유 계정입니다 — 일반 지갑이 아닐 수 있습니다".to_owned(),
        ));
    }
    if intent.has(flags::SIM_WARNING) {
        out.push(warning(
            L05,
            format!(
                "시뮬레이션에서 실패했거나 계산 한도를 넘었습니다 — 수수료만 잃을 수 있습니다\n{}",
                sim_text(facts.simulation, intent.core.cu_limit)
            ),
        ));
    }
    if intent.has(flags::FIRST_TIME) {
        out.push(warning(
            L06,
            "처음 보내는 주소입니다. 주소 전체를 확인하고, 큰 금액은 소액 시험 송금 뒤 보내세요."
                .to_owned(),
        ));
    }
    if intent.has(flags::NON_STANDARD_PATH) {
        out.push(warning(
            L07,
            format!("비표준 경로 계정입니다 ({})", intent.source.path_text()),
        ));
    }
    if intent.has(flags::SEND_MAX) {
        out.push(warning(
            L08,
            "보내기 최대: 보낸 뒤 이 계정의 SOL 잔액은 0이 됩니다".to_owned(),
        ));
    }
    out
}

fn fee_text(intent: &SolTransferIntent, facts: &SolPreviewFacts) -> String {
    let core = &intent.core;
    let priority = priority_fee(core.cu_limit, core.cu_price_micro).unwrap_or(u64::MAX);
    let rpc = match facts.rpc_fee {
        Some(rpc) if rpc < intent.max_fee_lamports => {
            format!("{} lamports (지갑 최대보다 낮은 RPC 추정)", format_raw(rpc))
        }
        Some(rpc) => format!("{} lamports", format_raw(rpc)),
        None => "확인하지 못함".to_owned(),
    };
    format!(
        "기본 수수료 {} lamports × 서명 1\n우선 수수료 {} lamports (CU 한도 {} × 가격 {} micro-lamports/CU, 올림)\n최대 합계 {} SOL ({} lamports)\n사용자 상한 {} lamports\nRPC getFeeForMessage: {rpc}",
        format_raw(SOL_BASE_FEE_LAMPORTS_PER_SIG),
        format_raw(priority),
        format_raw(u64::from(core.cu_limit)),
        format_raw(core.cu_price_micro),
        format_amount(intent.max_fee_lamports, 9),
        format_raw(intent.max_fee_lamports),
        format_raw(intent.fee_cap_lamports),
    )
}

fn recipient_text(core: &SolTransferCore, facts: &SolPreviewFacts) -> String {
    let mut text = grouped(&core.to);
    if let Some(exact) = &facts.recipient.exact {
        let name = escape_label(&exact.label);
        let _ = match exact.kind {
            KnownKind::Book { verified: true } => write!(text, "\n주소록: {name} ✓ 확인됨"),
            KnownKind::Book { verified: false } => write!(text, "\n주소록: {name}"),
            KnownKind::Own { index } => {
                write!(text, "\n내 계정 #{}: {name}", index.saturating_add(1))
            }
            KnownKind::Sent => write!(text, "\n보낸 적 있는 주소"),
        };
    }
    if facts.recipient_account == AccountClass::Missing {
        text.push_str("\n새 계정(아직 없음)");
    }
    text
}

fn balance_text(balance: u64, total: u64) -> String {
    let after = balance.checked_sub(total).map_or_else(
        || "부족".to_owned(),
        |rest| format!("{} SOL", format_amount(rest, 9)),
    );
    format!("{} SOL → {after} (RPC 기준)", format_amount(balance, 9))
}

/// Builds the draft of a SOL transfer (spec/07 §13.1-3); `genesis` is the hash checked with
/// `getGenesisHash` (equal to the cluster's pinned value).
///
/// # Errors
///
/// [`DisplayError`] (defensive: every string is built or escaped here).
pub fn build_sol_transfer_request(
    intent: &SolTransferIntent,
    genesis: &[u8; 32],
    facts: &SolPreviewFacts,
) -> Result<ApprovalDraft, DisplayError> {
    let core = &intent.core;
    let mut fields: Vec<DisplayField> = Vec::with_capacity(12);
    fields.push(DisplayField::new(
        FieldKey::ORIGIN,
        "",
        "Your Wallet 앱 (yw-app)",
    )?);
    fields.push(DisplayField::new(
        FieldKey::NETWORK,
        "",
        format!(
            "{}\ngenesis 확인됨: {}",
            intent.cluster.display_name(),
            crate::codec::base58::base58_encode(genesis)
        ),
    )?);
    fields.push(DisplayField::new(
        FieldKey::ACCOUNT,
        "",
        format!(
            "{}\n{}\n{}",
            escape_label(&facts.account_label),
            intent.source.path_text(),
            grouped(&core.from)
        ),
    )?);
    fields.push(DisplayField::new(
        FieldKey::SOL_TO,
        "",
        recipient_text(core, facts),
    )?);
    fields.push(DisplayField::new(
        FieldKey::SOL_AMOUNT,
        "",
        lamports_text(core.amount),
    )?);
    fields.push(DisplayField::new(
        FieldKey::SOL_FEE,
        "",
        fee_text(intent, facts),
    )?);
    let total = core.amount.saturating_add(intent.max_fee_lamports);
    fields.push(DisplayField::new(
        FieldKey::SOL_TOTAL,
        "",
        lamports_text(total),
    )?);
    fields.push(DisplayField::new(
        FieldKey::SOL_BALANCE,
        "",
        balance_text(facts.balance, total),
    )?);
    fields.push(DisplayField::new(
        FieldKey::SOL_SIMULATION,
        "",
        sim_text(facts.simulation, core.cu_limit),
    )?);
    fields.push(DisplayField::new(
        FieldKey::SOL_VALIDITY,
        "",
        "승인 창은 표시 후 120초에 만료(남은 시간은 상태 줄). 승인 즉시 서명하며 거래는 약 30초 뒤 만료",
    )?);
    fields.push(DisplayField::new(
        FieldKey::SOL_AUDIT,
        "intent_hash",
        crate::hex::encode(&intent.intent_hash()),
    )?);
    let display = ApprovalDisplay::new(
        transfer_title(intent.cluster, core),
        fields,
        warnings(intent, facts),
    )?;
    Ok(ApprovalDraft {
        id: ApprovalId(intent.id),
        origin: ApprovalOrigin::App,
        chain: ChainRef::Solana {
            cluster: intent.cluster,
            genesis: *genesis,
        },
        account: AccountRef::Sol(core.from.to_bytes()),
        signer: Signer::FromPayload,
        kind: ApprovalKind::SolTransfer,
        payload: SigningPayload::SolTransfer(*intent),
        display,
        simulation: SimulationBinding::NotApplicable,
    })
}
