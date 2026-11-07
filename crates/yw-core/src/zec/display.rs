//! The Zcash approval request (spec/12 §9): network, from (account and address), to (re-encoded
//! transparent address and the form it was entered in), amount, change, fee, total, expiry
//! height with the network upgrade, inputs and the advanced block. Every value is built from the
//! plan; no server string is shown.
#![deny(clippy::indexing_slicing)]

use super::address::RecipientForm;
use super::plan::ZecPlan;
use super::sign::zec_payload;
use super::{format_zec, format_zec_and_zats};
use crate::approval::{
    AccountRef, ApprovalDisplay, ApprovalDraft, ApprovalId, ApprovalKind, ApprovalOrigin, ChainRef,
    DisplayError, DisplayField, FieldKey, RiskLevel, RuleId, Signer, SigningPayload,
    SimulationBinding, Warning,
};

/// Z01: the recipient is our own address (information).
pub const RULE_OWN_ADDRESS: RuleId = RuleId::new(b'Z', 1);
/// Z02: TEX recipient (information: fully transparent by construction).
pub const RULE_TEX: RuleId = RuleId::new(b'Z', 2);
/// Z03: UA recipient whose transparent receiver is used (caution: the payee gets public funds).
pub const RULE_UA_TRANSPARENT: RuleId = RuleId::new(b'Z', 3);
/// Z04: a pending network upgrade capped the expiry (information).
pub const RULE_EXPIRY_CAPPED: RuleId = RuleId::new(b'Z', 4);
/// Z05: transparent sends are public (always shown).
pub const RULE_PUBLIC: RuleId = RuleId::new(b'Z', 5);

fn warning(rule: RuleId, level: RiskLevel, text: &str) -> Warning {
    Warning {
        rule,
        level,
        text: text.to_owned(),
    }
}

/// The warnings of a plan.
#[must_use]
pub fn plan_warnings(plan: &ZecPlan) -> Vec<Warning> {
    let mut out = vec![warning(
        RULE_PUBLIC,
        RiskLevel::Info,
        "일반(transparent) 전송은 보내는 주소·받는 주소·금액이 블록체인에 공개됩니다.",
    )];
    if plan.to_self() {
        out.push(warning(
            RULE_OWN_ADDRESS,
            RiskLevel::Info,
            "받는 주소가 이 계정의 주소입니다 (수수료만 나갑니다).",
        ));
    }
    match plan.recipient.form {
        RecipientForm::Tex => out.push(warning(
            RULE_TEX,
            RiskLevel::Info,
            "TEX 주소: 받는 사람이 일반(transparent) 자금만 받겠다고 요청한 주소입니다. 이 거래는 일반 입력만 씁니다.",
        )),
        RecipientForm::Unified => out.push(warning(
            RULE_UA_TRANSPARENT,
            RiskLevel::Caution,
            "통합 주소(UA)의 일반(transparent) 수신자로 보냅니다. 받는 지갑에는 비공개가 아닌 일반 잔액으로 들어갑니다.",
        )),
        RecipientForm::Transparent => {}
    }
    if plan
        .consensus
        .next_upgrade_height
        .is_some_and(|height| plan.consensus.expiry_height.saturating_add(1) == height)
    {
        out.push(warning(
            RULE_EXPIRY_CAPPED,
            RiskLevel::Info,
            "다음 네트워크 업그레이드 전에 만료되도록 만료 높이를 앞당겼습니다.",
        ));
    }
    out
}

fn account_text(plan: &ZecPlan) -> String {
    let account = &plan.account;
    format!(
        "Zcash {} · {}\n{}",
        account.source.label(),
        account.source.path_text(account.network),
        account.address()
    )
}

fn to_text(plan: &ZecPlan) -> String {
    let encoded = plan.recipient.dest.encode(plan.account.network);
    match plan.recipient.form {
        RecipientForm::Transparent => encoded,
        RecipientForm::Tex | RecipientForm::Unified => {
            format!("{encoded}\n입력한 주소: {}", plan.recipient.text)
        }
    }
}

fn change_text(plan: &ZecPlan) -> String {
    if plan.change > 0 {
        format!(
            "{} ZEC — 같은 주소로 돌아옴 {}",
            format_zec(plan.change),
            plan.account.address()
        )
    } else if plan.fee > plan.conventional_fee {
        format!(
            "잔돈 없음: {} zats 수수료에 추가",
            crate::btc::amount::format_sats_grouped(plan.fee - plan.conventional_fee)
        )
    } else {
        "잔돈 없음".to_owned()
    }
}

fn fee_text(plan: &ZecPlan) -> String {
    format!(
        "{}\nZIP 317 기본 수수료 {} zats (입력 {}개, 출력 {}개)",
        format_zec_and_zats(plan.fee),
        crate::btc::amount::format_sats_grouped(plan.conventional_fee),
        plan.inputs.len(),
        plan.tx.outputs.len()
    )
}

fn expiry_text(plan: &ZecPlan) -> String {
    let consensus = &plan.consensus;
    let blocks = consensus
        .expiry_height
        .saturating_sub(consensus.next_height)
        .saturating_add(1);
    let minutes = u64::from(blocks) * u64::from(consensus.block_secs) / 60;
    let mut text = format!(
        "블록 {} (다음 블록 {}부터 {blocks}블록, 약 {minutes}분 안에 포함되지 않으면 무효)\n네트워크 업그레이드 {} (branch id {:08x})",
        consensus.expiry_height, consensus.next_height, consensus.upgrade_name, consensus.branch_id
    );
    if let Some(height) = consensus.next_upgrade_height {
        text.push_str("\n다음 업그레이드 활성화 높이 ");
        text.push_str(&height.to_string());
    }
    text
}

fn inputs_text(plan: &ZecPlan) -> String {
    let excluded = if plan.excluded_inputs > 0 {
        format!(
            "\n가장 큰 입력 {}개만 씁니다 — 나머지 {}개는 이 주소에 남습니다",
            plan.inputs.len(),
            plan.excluded_inputs
        )
    } else {
        String::new()
    };
    format!(
        "{}개, 합계 {}\n입력 금액과 스크립트는 서명(ZIP 244)에 포함되어, 틀리면 거래가 무효가 됩니다{excluded}",
        plan.inputs.len(),
        format_zec_and_zats(plan.input_total())
    )
}

fn advanced_text(plan: &ZecPlan) -> String {
    format!(
        "v5 거래 (ZIP 225), 일반(transparent) 입력·출력만\nnLockTime 0 · sequence 0xFFFFFFFF\nSIGHASH_ALL (ZIP 244)\n{}",
        if plan.send_max {
            "보내기 최대: 모든 확인된 잔액 − 수수료"
        } else {
            "지정 금액"
        }
    )
}

/// Builds the approval draft (spec/12 §9): origin `App`, chain `Zcash` with the network's pinned
/// genesis, account = the account public key, `Signer::FromPayload`, payload
/// [`zec_payload`], no simulation.
///
/// # Errors
///
/// [`DisplayError`] (defensive).
pub fn build_zec_request(id: ApprovalId, plan: &ZecPlan) -> Result<ApprovalDraft, DisplayError> {
    let network = plan.account.network;
    let total = plan
        .amount
        .checked_add(plan.fee)
        .ok_or(DisplayError::InvalidText)?;
    let fields = vec![
        DisplayField::new(FieldKey::ORIGIN, "", crate::approval::APP_ORIGIN_TEXT)?,
        DisplayField::new(FieldKey::NETWORK, "", network.banner())?,
        DisplayField::new(FieldKey::ACCOUNT, "", account_text(plan))?,
        DisplayField::new(FieldKey::ZEC_TO, "", to_text(plan))?,
        DisplayField::new(FieldKey::ZEC_FORM, "", plan.recipient.form.label())?,
        DisplayField::new(FieldKey::ZEC_AMOUNT, "", format_zec_and_zats(plan.amount))?,
        DisplayField::new(FieldKey::ZEC_CHANGE, "", change_text(plan))?,
        DisplayField::new(FieldKey::ZEC_FEE, "", fee_text(plan))?,
        DisplayField::new(FieldKey::ZEC_TOTAL, "", format_zec_and_zats(total))?,
        DisplayField::new(FieldKey::ZEC_EXPIRY, "", expiry_text(plan))?,
        DisplayField::new(FieldKey::ZEC_INPUTS, "", inputs_text(plan))?,
        DisplayField::new(FieldKey::ZEC_ADVANCED, "", advanced_text(plan))?,
    ];
    let display = ApprovalDisplay::new(
        format!(
            "[{}] 보내기: {} ZEC",
            network.display_name(),
            format_zec(plan.amount)
        ),
        fields,
        plan_warnings(plan),
    )?;
    Ok(ApprovalDraft {
        id,
        origin: ApprovalOrigin::App,
        chain: ChainRef::Zcash {
            network: network.id(),
            genesis: network.genesis(),
        },
        account: AccountRef::Zcash(plan.account.pubkey),
        signer: Signer::FromPayload,
        kind: ApprovalKind::ZecSend,
        payload: SigningPayload::Zec(zec_payload(plan)),
        display,
        simulation: SimulationBinding::NotApplicable,
    })
}
