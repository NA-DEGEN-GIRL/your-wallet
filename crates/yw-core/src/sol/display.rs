//! The SOL/SPL approval request (spec/07 §13.3): title, display fields `0x0001`–`0x0003` and
//! `0x0501`–`0x0509`, and the `L01`–`L08` warnings (`RuleId` family `'L'`, spec/03 §10.1).
//! Strings that come from the user (labels) are escaped; nothing from RPC is shown verbatim.
//! SPL amounts, symbols, mints, decimals and token programs come from the pinned allowlist and
//! the ATAs from the local derivation; RPC values (balances, ATA existence, rent) are marked as
//! references.

use core::fmt::Write as _;

use super::address::{SolCluster, grouped};
use super::broadcast::err;
use super::fee::{FeeError, SOL_BASE_FEE_LAMPORTS_PER_SIG, priority_fee};
use super::intent::{SolTransferIntent, flags};
use super::recipient::{AccountClass, KnownKind, RecipientCheck};
use super::rent::{RentError, format_amount, format_raw};
use super::sign::fee_policy_ok;
use super::template::{SolAsset, SolTransferCore, SplAccounts};
use super::text as t;
use crate::approval::{
    AccountRef, ApprovalDisplay, ApprovalDraft, ApprovalId, ApprovalKind, ApprovalOrigin, ChainRef,
    DisplayError, DisplayField, FieldKey, MAX_TITLE_BYTES, RiskLevel, RuleId, Signer,
    SigningPayload, SimulationBinding, Warning, escape_edges, escape_untrusted,
};
use crate::lang::Lang;
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
    /// Rent, balance or token-balance rule.
    Rent(RentError),
    /// The recipient is a token account or mint (§12.2).
    RecipientIsTokenAccount,
    /// The recipient is an executable program (§12.2).
    RecipientIsProgram,
    /// An implausible RPC value (`lastValidBlockHeight`, rent, mint data that disagrees with the
    /// pinned allowlist, a foreign account at the sender's ATA address).
    RpcAnomaly,
    /// A `Pending` transfer of the same (cluster, account) exists.
    PendingExists,
    /// No room in the journal (`JournalError::Full`, E-TX-005).
    JournalFull,
    /// SPL: the sender's token account is frozen (§15.4).
    TokenAccountFrozen,
    /// SPL: the recipient's ATA exists but is frozen or not a token account of this mint and
    /// wallet (§15.4).
    RecipientTokenAccountUnusable,
}

impl SolBlock {
    /// Fixed reason text in Korean ([`Self::text_in`] for a language).
    #[must_use]
    pub fn text(self) -> String {
        self.text_in(Lang::Ko)
    }

    /// Fixed reason text in `lang`.
    #[must_use]
    pub fn text_in(self, lang: Lang) -> String {
        let text = match self {
            Self::ClusterMismatch => t::BLOCK_CLUSTER_MISMATCH,
            Self::Fee(error) => return error.text_in(lang).to_owned(),
            Self::Rent(error) => return error.text_in(lang),
            Self::RecipientIsTokenAccount => t::BLOCK_TOKEN_ACCOUNT,
            Self::RecipientIsProgram => t::BLOCK_PROGRAM,
            Self::RpcAnomaly => t::RPC_ANOMALY,
            Self::PendingExists => t::BLOCK_PENDING,
            Self::JournalFull => t::BLOCK_JOURNAL_FULL,
            Self::TokenAccountFrozen => t::BLOCK_FROZEN,
            Self::RecipientTokenAccountUnusable => t::BLOCK_RECIPIENT_ATA,
        };
        text.get(lang).to_owned()
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

/// SPL facts of the step-2 preview (RPC references, v1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplPreviewFacts {
    /// `from_ata` raw balance (`None`: no usable token account).
    pub token_balance: Option<u64>,
    /// `getAccountInfo(to_ata)` returned an account.
    pub to_ata_exists: bool,
    /// `getMinimumBalanceForRentExemption(165)`.
    pub rent165: u64,
}

impl SplPreviewFacts {
    /// The rent the sender pays for the destination ATA (`rent165` when it is missing).
    #[must_use]
    pub const fn rent(&self) -> u64 {
        if self.to_ata_exists { 0 } else { self.rent165 }
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
    /// SPL facts (`None` for SOL).
    pub spl: Option<SplPreviewFacts>,
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
    if source.needs_move_rule() {
        out |= flags::NON_STANDARD_PATH;
    }
    out
}

fn escape_label(lang: Lang, text: &str) -> String {
    let escaped = escape_untrusted(text).text.replace('\n', "[U+000A]");
    let value = escape_edges(&escaped);
    if value.is_empty() {
        t::NO_NAME.get(lang).to_owned()
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

/// `1.000000 USDC` (pinned decimals and symbol of the asset; SOL as `1.000000000 SOL`).
#[must_use]
pub fn asset_amount_text(asset: SolAsset, raw: u64) -> String {
    format!(
        "{} {}",
        format_amount(raw, asset.decimals()),
        asset.symbol()
    )
}

/// The approval title of a transfer (`[Solana devnet (테스트)] SOL 전송: 1.000000000 SOL`,
/// `[Solana mainnet] 토큰 전송: 1.000000 USDC`). The journal activity rebuilds the same string
/// from the transaction bytes (spec/07 §14.1). Korean; [`transfer_title_in`] for a language.
#[must_use]
pub fn transfer_title(cluster: SolCluster, core: &SolTransferCore) -> String {
    transfer_title_in(Lang::Ko, cluster, core)
}

/// [`transfer_title`] in `lang` (`[Solana devnet (test)] SOL transfer: 1.000000000 SOL`).
#[must_use]
pub fn transfer_title_in(lang: Lang, cluster: SolCluster, core: &SolTransferCore) -> String {
    let kind = match core.asset {
        SolAsset::Sol => t::TITLE_SOL_TRANSFER,
        SolAsset::Spl(_) => t::TITLE_TOKEN_TRANSFER,
    }
    .get(lang);
    let network = cluster.display_name_in(lang);
    let title = format!(
        "[{network}] {kind}: {}",
        asset_amount_text(core.asset, core.amount)
    );
    if title.len() <= MAX_TITLE_BYTES {
        title
    } else {
        format!("[{network}] {kind}")
    }
}

fn warning(rule: RuleId, text: String) -> Warning {
    Warning {
        rule,
        level: level_of(rule).unwrap_or(RiskLevel::High),
        text,
    }
}

fn lookalike_text(lang: Lang, recipient: &RecipientCheck) -> String {
    let mut lines = vec![t::LOOKALIKE_HEAD.get(lang).to_owned()];
    for entry in &recipient.lookalikes {
        let name = escape_label(lang, &entry.label);
        let address = grouped(&entry.address);
        lines.push(match &entry.kind {
            KnownKind::Book { .. } => t::LOOKALIKE_BOOK.fill(lang, [&name, &address]),
            KnownKind::Own { .. }
            | KnownKind::OwnImported
            | KnownKind::OwnHardware
            | KnownKind::OwnMnemonic => t::LOOKALIKE_OWN.fill(lang, [&name, &address]),
            KnownKind::Sent | KnownKind::History => t::LOOKALIKE_SENT.fill(lang, [&address]),
        });
    }
    lines.join("\n")
}

fn sim_text(lang: Lang, simulation: SimSummary, cu_limit: u32) -> String {
    match simulation {
        SimSummary::Ok { units } if units > u64::from(cu_limit) => {
            t::SIM_CU_OVER.fill(lang, [&units.to_string(), &cu_limit.to_string()])
        }
        SimSummary::Ok { units } => t::SIM_OK.fill(lang, [&units.to_string()]),
        SimSummary::Failed { err: code, .. } => {
            t::SIM_FAILED.fill(lang, [err::text_in(code, lang)])
        }
        SimSummary::NoResult => t::SIM_NO_RESULT.get(lang).to_owned(),
    }
}

fn warnings(lang: Lang, intent: &SolTransferIntent, facts: &SolPreviewFacts) -> Vec<Warning> {
    let mut out: Vec<Warning> = facts
        .blocks
        .iter()
        .map(|block| warning(L01, t::L01_CAUSE.fill(lang, [&block.text_in(lang)])))
        .collect();
    if intent.has(flags::OFF_CURVE) {
        out.push(warning(L02, t::L02_TEXT.get(lang).to_owned()));
    }
    if intent.has(flags::LOOKALIKE) {
        out.push(warning(L03, lookalike_text(lang, &facts.recipient)));
    }
    if intent.has(flags::PROGRAM_OWNED) {
        out.push(warning(L04, t::L04_TEXT.get(lang).to_owned()));
    }
    if intent.has(flags::SIM_WARNING) {
        let sim = sim_text(lang, facts.simulation, intent.core.cu_limit);
        out.push(warning(L05, t::L05_TEXT.fill(lang, [&sim])));
    }
    if intent.has(flags::FIRST_TIME) {
        out.push(warning(L06, t::L06_TEXT.get(lang).to_owned()));
    }
    if intent.has(flags::NON_STANDARD_PATH) {
        out.push(warning(
            L07,
            t::L07_TEXT.fill(lang, [&intent.source.path_text_in(lang)]),
        ));
    }
    if intent.has(flags::SEND_MAX) {
        out.push(warning(
            L08,
            match intent.core.asset {
                SolAsset::Sol => t::L08_SOL.get(lang).to_owned(),
                SolAsset::Spl(entry) => t::L08_SPL.fill(lang, [entry.symbol]),
            },
        ));
    }
    out
}

fn fee_text(lang: Lang, intent: &SolTransferIntent, facts: &SolPreviewFacts) -> String {
    let core = &intent.core;
    let priority = priority_fee(core.cu_limit, core.cu_price_micro).unwrap_or(u64::MAX);
    let rpc = match facts.rpc_fee {
        Some(rpc) if rpc < intent.max_fee_lamports => {
            t::FEE_RPC_LOWER.fill(lang, [&format_raw(rpc)])
        }
        Some(rpc) => format!("{} lamports", format_raw(rpc)),
        None => t::NOT_CHECKED.get(lang).to_owned(),
    };
    t::FEE_TEXT.fill(
        lang,
        [
            &format_raw(SOL_BASE_FEE_LAMPORTS_PER_SIG),
            &format_raw(priority),
            &format_raw(u64::from(core.cu_limit)),
            &format_raw(core.cu_price_micro),
            &format_amount(intent.max_fee_lamports, 9),
            &format_raw(intent.max_fee_lamports),
            &format_raw(intent.fee_cap_lamports),
            &rpc,
        ],
    )
}

fn recipient_text(lang: Lang, core: &SolTransferCore, facts: &SolPreviewFacts) -> String {
    let mut text = grouped(&core.to);
    if let Some(exact) = &facts.recipient.exact {
        let name = escape_label(lang, &exact.label);
        let note = match exact.kind {
            KnownKind::Book { verified: true } => t::RECIPIENT_BOOK_VERIFIED.fill(lang, [&name]),
            KnownKind::Book { verified: false } => t::RECIPIENT_BOOK.fill(lang, [&name]),
            KnownKind::Own { index } => {
                t::RECIPIENT_OWN.fill(lang, [&index.saturating_add(1).to_string(), &name])
            }
            KnownKind::OwnImported => t::RECIPIENT_OWN_IMPORTED.fill(lang, [&name]),
            KnownKind::OwnHardware => t::RECIPIENT_OWN_HARDWARE.fill(lang, [&name]),
            KnownKind::OwnMnemonic => t::RECIPIENT_OWN_MNEMONIC.fill(lang, [&name]),
            KnownKind::Sent | KnownKind::History => t::RECIPIENT_SENT.get(lang).to_owned(),
        };
        let _ = write!(text, "\n{note}");
    }
    if facts.recipient_account == AccountClass::Missing {
        let note = match core.asset {
            SolAsset::Sol => t::RECIPIENT_NEW,
            SolAsset::Spl(_) => t::RECIPIENT_NO_SOL_ACCOUNT,
        };
        text.push('\n');
        text.push_str(note.get(lang));
    }
    if matches!(core.asset, SolAsset::Spl(_)) {
        text.push('\n');
        text.push_str(t::RECIPIENT_SPL_OWNER.get(lang));
    }
    text
}

/// `0x0502` for SPL: symbol, UI and raw amount, mint, token program, decimals, both ATAs.
fn spl_amount_text(lang: Lang, core: &SolTransferCore, accounts: &SplAccounts) -> String {
    let entry = accounts.entry;
    t::SPL_AMOUNT.fill(
        lang,
        [
            &asset_amount_text(core.asset, core.amount),
            &format_raw(core.amount),
            &entry.decimals.to_string(),
            &grouped(&entry.mint),
            &grouped(&accounts.from_ata),
            &grouped(&accounts.to_ata),
        ],
    )
}

/// `0x0503`: the destination ATA creation and who pays its rent.
fn ata_text(lang: Lang, spl: &SplPreviewFacts) -> String {
    let template = if spl.to_ata_exists {
        t::ATA_EXISTS
    } else {
        t::ATA_MISSING
    };
    template.fill(
        lang,
        [&format_amount(spl.rent165, 9), &format_raw(spl.rent165)],
    )
}

fn balance_text(lang: Lang, balance: u64, total: u64) -> String {
    let after = balance.checked_sub(total).map_or_else(
        || t::INSUFFICIENT.get(lang).to_owned(),
        |rest| format!("{} SOL", format_amount(rest, 9)),
    );
    t::BALANCE_AFTER.fill(lang, [&format_amount(balance, 9), &after])
}

fn token_balance_text(lang: Lang, asset: SolAsset, balance: Option<u64>, amount: u64) -> String {
    match balance {
        Some(balance) => {
            let after = balance.checked_sub(amount).map_or_else(
                || t::INSUFFICIENT.get(lang).to_owned(),
                |rest| asset_amount_text(asset, rest),
            );
            t::TOKEN_BALANCE_AFTER.fill(lang, [&asset_amount_text(asset, balance), &after])
        }
        None => t::NO_TOKEN_ACCOUNT_BALANCE.fill(lang, [asset.symbol()]),
    }
}

/// The SOL the transfer can take at most: amount (SOL only) + maximum fee + the possible ATA
/// rent (SPL, when RPC says the destination ATA is missing).
#[must_use]
pub fn max_sol_debit(intent: &SolTransferIntent, facts: &SolPreviewFacts) -> u64 {
    match intent.core.asset {
        SolAsset::Sol => intent.core.amount.saturating_add(intent.max_fee_lamports),
        SolAsset::Spl(_) => intent
            .max_fee_lamports
            .saturating_add(facts.spl.map_or(0, |spl| spl.rent())),
    }
}

/// The asset-specific fields `0x0502`–`0x0506` (spec/07 §13.3): SOL amount, fee, total and
/// balance; SPL adds `0x0503` (ATA creation and its rent) and the token side of each.
fn asset_fields(
    lang: Lang,
    fields: &mut Vec<DisplayField>,
    intent: &SolTransferIntent,
    facts: &SolPreviewFacts,
) -> Result<(), DisplayError> {
    let core = &intent.core;
    let total = max_sol_debit(intent, facts);
    match core.asset {
        SolAsset::Sol => {
            fields.push(DisplayField::new(
                FieldKey::SOL_AMOUNT,
                "",
                lamports_text(core.amount),
            )?);
            fields.push(DisplayField::new(
                FieldKey::SOL_FEE,
                "",
                fee_text(lang, intent, facts),
            )?);
            fields.push(DisplayField::new(
                FieldKey::SOL_TOTAL,
                "",
                lamports_text(total),
            )?);
            fields.push(DisplayField::new(
                FieldKey::SOL_BALANCE,
                "",
                balance_text(lang, facts.balance, total),
            )?);
        }
        SolAsset::Spl(entry) => {
            let (Some(accounts), Some(spl)) = (SplAccounts::of(core), facts.spl) else {
                return Err(DisplayError::InvalidText);
            };
            fields.push(DisplayField::new(
                FieldKey::SOL_AMOUNT,
                entry.symbol,
                spl_amount_text(lang, core, &accounts),
            )?);
            fields.push(DisplayField::new(
                FieldKey::SOL_ATA,
                "",
                ata_text(lang, &spl),
            )?);
            fields.push(DisplayField::new(
                FieldKey::SOL_FEE,
                "",
                fee_text(lang, intent, facts),
            )?);
            fields.push(DisplayField::new(
                FieldKey::SOL_TOTAL,
                "",
                t::SPL_TOTAL.fill(
                    lang,
                    [
                        &asset_amount_text(core.asset, core.amount),
                        &format_amount(total, 9),
                        &format_raw(total),
                        &format_raw(intent.max_fee_lamports),
                        &format_raw(spl.rent()),
                    ],
                ),
            )?);
            fields.push(DisplayField::new(
                FieldKey::SOL_BALANCE,
                "",
                format!(
                    "{}\n{}",
                    token_balance_text(lang, core.asset, spl.token_balance, core.amount),
                    balance_text(lang, facts.balance, total)
                ),
            )?);
        }
    }
    Ok(())
}

/// Builds the draft of a SOL or SPL transfer (spec/07 §13.1-3) with every text in `lang`;
/// `genesis` is the hash checked with `getGenesisHash` (equal to the cluster's pinned value).
///
/// # Errors
///
/// [`DisplayError`] (defensive: every string is built or escaped here; an SPL intent without
/// derivable accounts or preview facts is refused the same way, and so is an intent whose
/// compute-unit limit is not the template's, whose maximum fee is not the formula's value or
/// exceeds the cap, or whose recipient is not the one the shown recipient check parsed).
pub fn build_sol_transfer_request(
    lang: Lang,
    intent: &SolTransferIntent,
    genesis: &[u8; 32],
    facts: &SolPreviewFacts,
) -> Result<ApprovalDraft, DisplayError> {
    let core = &intent.core;
    if !fee_policy_ok(intent) || facts.recipient.to != core.to {
        return Err(DisplayError::InvalidText);
    }
    let mut fields: Vec<DisplayField> = Vec::with_capacity(13);
    fields.push(DisplayField::new(
        FieldKey::ORIGIN,
        "",
        crate::approval::APP_ORIGIN.get(lang),
    )?);
    fields.push(DisplayField::new(
        FieldKey::NETWORK,
        "",
        t::NETWORK_GENESIS.fill(
            lang,
            [
                intent.cluster.display_name_in(lang),
                &crate::codec::base58::base58_encode(genesis),
            ],
        ),
    )?);
    fields.push(DisplayField::new(
        FieldKey::ACCOUNT,
        "",
        format!(
            "{}\n{}\n{}",
            escape_label(lang, &facts.account_label),
            intent.source.path_text_in(lang),
            grouped(&core.from)
        ),
    )?);
    fields.push(DisplayField::new(
        FieldKey::SOL_TO,
        "",
        recipient_text(lang, core, facts),
    )?);
    asset_fields(lang, &mut fields, intent, facts)?;
    fields.push(DisplayField::new(
        FieldKey::SOL_SIMULATION,
        "",
        sim_text(lang, facts.simulation, core.cu_limit),
    )?);
    fields.push(DisplayField::new(
        FieldKey::SOL_VALIDITY,
        "",
        t::VALIDITY.get(lang),
    )?);
    fields.push(DisplayField::new(
        FieldKey::SOL_AUDIT,
        "intent_hash",
        crate::hex::encode(&intent.intent_hash()),
    )?);
    let display = ApprovalDisplay::new(
        lang,
        transfer_title_in(lang, intent.cluster, core),
        fields,
        warnings(lang, intent, facts),
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
