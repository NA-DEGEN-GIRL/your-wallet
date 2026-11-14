//! The Zcash approval request (spec/12 §9): network, from (account and address), to (re-encoded
//! transparent address and the form it was entered in), amount, change, fee, total, expiry
//! height with the network upgrade, inputs and the advanced block. Every value is built from the
//! plan; no server string is shown.
#![deny(clippy::indexing_slicing)]

use super::address::RecipientForm;
use super::plan::ZecPlan;
use super::sign::zec_payload;
use super::text;
use super::{format_zec, format_zec_and_zats};
use crate::approval::{
    AccountRef, ApprovalDisplay, ApprovalDraft, ApprovalId, ApprovalKind, ApprovalOrigin, ChainRef,
    DisplayError, DisplayField, FieldKey, RiskLevel, RuleId, Signer, SigningPayload,
    SimulationBinding, Warning,
};
use crate::lang::Lang;

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
/// Z06: no confirmed send of this wallet went to the recipient yet (caution).
pub const RULE_FIRST_TIME: RuleId = RuleId::new(b'Z', 6);

fn warning(rule: RuleId, level: RiskLevel, text: &str) -> Warning {
    Warning {
        rule,
        level,
        text: text.to_owned(),
    }
}

/// The warnings of a plan, in `lang`.
#[must_use]
pub fn plan_warnings(lang: Lang, plan: &ZecPlan) -> Vec<Warning> {
    let mut out = vec![warning(
        RULE_PUBLIC,
        RiskLevel::Info,
        text::Z05_PUBLIC.get(lang),
    )];
    if plan.to_self() {
        out.push(warning(
            RULE_OWN_ADDRESS,
            RiskLevel::Info,
            text::Z01_OWN_ADDRESS.get(lang),
        ));
    }
    match plan.recipient.form {
        RecipientForm::Tex => out.push(warning(RULE_TEX, RiskLevel::Info, text::Z02_TEX.get(lang))),
        RecipientForm::Unified => out.push(warning(
            RULE_UA_TRANSPARENT,
            RiskLevel::Caution,
            text::Z03_UA_TRANSPARENT.get(lang),
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
            text::Z04_EXPIRY_CAPPED.get(lang),
        ));
    }
    out
}

fn account_text(lang: Lang, plan: &ZecPlan) -> String {
    let account = &plan.account;
    format!(
        "Zcash {} · {}\n{}",
        text::source_label(lang, account.source),
        text::path_text(lang, account.source, account.network),
        account.address()
    )
}

fn to_text(lang: Lang, plan: &ZecPlan) -> String {
    let encoded = plan.recipient.dest.encode(plan.account.network);
    match plan.recipient.form {
        RecipientForm::Transparent => encoded,
        RecipientForm::Tex | RecipientForm::Unified => {
            text::TO_ENTERED.fill(lang, [&encoded, &plan.recipient.text])
        }
    }
}

fn change_text(lang: Lang, plan: &ZecPlan) -> String {
    if plan.change > 0 {
        text::CHANGE_BACK.fill(lang, [&format_zec(plan.change), &plan.account.address()])
    } else if plan.fee > plan.conventional_fee {
        text::CHANGE_FOLDED.fill(
            lang,
            [&crate::btc::amount::format_sats_grouped(
                plan.fee - plan.conventional_fee,
            )],
        )
    } else {
        text::CHANGE_NONE.get(lang).to_owned()
    }
}

fn fee_text(lang: Lang, plan: &ZecPlan) -> String {
    text::FEE.fill(
        lang,
        [
            &format_zec_and_zats(plan.fee),
            &crate::btc::amount::format_sats_grouped(plan.conventional_fee),
            &plan.inputs.len().to_string(),
            &plan.tx.outputs.len().to_string(),
        ],
    )
}

fn expiry_text(lang: Lang, plan: &ZecPlan) -> String {
    let consensus = &plan.consensus;
    let blocks = consensus
        .expiry_height
        .saturating_sub(consensus.next_height)
        .saturating_add(1);
    let minutes = u64::from(blocks) * u64::from(consensus.block_secs) / 60;
    let mut out = text::EXPIRY.fill(
        lang,
        [
            &consensus.expiry_height.to_string(),
            &consensus.next_height.to_string(),
            &blocks.to_string(),
            &minutes.to_string(),
            consensus.upgrade_name,
            &format!("{:08x}", consensus.branch_id),
        ],
    );
    if let Some(height) = consensus.next_upgrade_height {
        out.push('\n');
        out.push_str(&text::EXPIRY_NEXT_UPGRADE.fill(lang, [&height.to_string()]));
    }
    out
}

fn inputs_text(lang: Lang, plan: &ZecPlan) -> String {
    let mut out = text::INPUTS.fill(
        lang,
        [
            &plan.inputs.len().to_string(),
            &format_zec_and_zats(plan.input_total()),
        ],
    );
    if plan.excluded_inputs > 0 {
        out.push('\n');
        out.push_str(&text::INPUTS_EXCLUDED.fill(
            lang,
            [
                &plan.inputs.len().to_string(),
                &plan.excluded_inputs.to_string(),
            ],
        ));
    }
    out
}

fn advanced_text(lang: Lang, plan: &ZecPlan) -> String {
    let amount = if plan.send_max {
        text::ADVANCED_SEND_MAX
    } else {
        text::ADVANCED_FIXED
    };
    text::ADVANCED.fill(lang, [amount.get(lang)])
}

/// Builds the approval draft in `lang` (spec/12 §9, spec/14): origin `App`, chain `Zcash` with
/// the network's pinned genesis, account = the account public key, `Signer::FromPayload`, payload
/// [`zec_payload`], no simulation.
///
/// # Errors
///
/// [`DisplayError`] (defensive).
pub fn build_zec_request(
    lang: Lang,
    id: ApprovalId,
    plan: &ZecPlan,
) -> Result<ApprovalDraft, DisplayError> {
    build_zec_request_with(lang, id, plan, false)
}

/// [`build_zec_request`] with Z06 (caution: "처음 보내는 주소입니다…") when `first_time` — no
/// confirmed send of this wallet went to the recipient yet (the app knows its journal).
///
/// # Errors
///
/// [`DisplayError`] (defensive).
pub fn build_zec_request_with(
    lang: Lang,
    id: ApprovalId,
    plan: &ZecPlan,
    first_time: bool,
) -> Result<ApprovalDraft, DisplayError> {
    let network = plan.account.network;
    let mut warnings = plan_warnings(lang, plan);
    if first_time && !plan.to_self() {
        warnings.push(warning(
            RULE_FIRST_TIME,
            RiskLevel::Caution,
            text::Z06_FIRST_TIME.get(lang),
        ));
    }
    let total = plan
        .amount
        .checked_add(plan.fee)
        .ok_or(DisplayError::InvalidText)?;
    let fields = vec![
        DisplayField::new(FieldKey::ORIGIN, "", crate::approval::APP_ORIGIN.get(lang))?,
        DisplayField::new(FieldKey::NETWORK, "", text::network_banner(lang, network))?,
        DisplayField::new(FieldKey::ACCOUNT, "", account_text(lang, plan))?,
        DisplayField::new(FieldKey::ZEC_TO, "", to_text(lang, plan))?,
        DisplayField::new(
            FieldKey::ZEC_FORM,
            "",
            text::form_label(lang, plan.recipient.form),
        )?,
        DisplayField::new(FieldKey::ZEC_AMOUNT, "", format_zec_and_zats(plan.amount))?,
        DisplayField::new(FieldKey::ZEC_CHANGE, "", change_text(lang, plan))?,
        DisplayField::new(FieldKey::ZEC_FEE, "", fee_text(lang, plan))?,
        DisplayField::new(FieldKey::ZEC_TOTAL, "", format_zec_and_zats(total))?,
        DisplayField::new(FieldKey::ZEC_EXPIRY, "", expiry_text(lang, plan))?,
        DisplayField::new(FieldKey::ZEC_INPUTS, "", inputs_text(lang, plan))?,
        DisplayField::new(FieldKey::ZEC_ADVANCED, "", advanced_text(lang, plan))?,
    ];
    let display = ApprovalDisplay::new(
        lang,
        text::TITLE.fill(lang, [network.display_name(), &format_zec(plan.amount)]),
        fields,
        warnings,
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
