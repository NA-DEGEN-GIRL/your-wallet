//! The BTC approval request (spec/08 §10): the signing payload `btc_payload` (the
//! `SigningPayload::Btc` digest bytes), the title, the display fields `0x0001`–`0x0003`,
//! `0x0601`–`0x0609`, `0x0640`, and the `B01`–`B08` warnings. Every value is built here from the
//! plan and verified data; the recipient is always re-encoded from its output script and no
//! server string is shown.
#![deny(clippy::indexing_slicing)]

use super::account::{BtcAccountId, BtcAccountKey};
use super::address::{encode_address, kind_from_script};
use super::amount::{Sats, format_btc, format_btc_and_sats, format_sats_grouped};
use super::fee::{FeeRate, rate_kvb};
use super::network::BtcNetwork;
use super::policy::BtcWarning;
use super::select::SendPlan;
use super::text;
use super::tx::serialize;
use super::{BTC_SEQUENCE, BTC_TX_VERSION};
use crate::approval::{
    AccountRef, ApprovalDisplay, ApprovalDraft, ApprovalId, ApprovalOrigin, ChainRef, DisplayError,
    DisplayField, FieldKey, Signer, SigningPayload, SimulationBinding, Warning,
};
use crate::bip32::path::BtcChain;
use crate::lang::Lang;

/// Facts from the app that are shown but not part of the plan (spec/08 §10).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BtcSendFacts {
    /// Spendable verified balance (`BtcMeta::balance(..).available`, in-flight excluded).
    pub verified_balance: Sats,
    /// Smallest confirmation count of the plan's inputs (server based), if known.
    pub min_confirmations: Option<u32>,
    /// The recipient script's SHA-256 is not in `BtcMeta.sent_scripts` (B05).
    pub first_time_recipient: bool,
    /// The recipient is our address `(chain, index)` of the spending account (B07).
    pub own_recipient: Option<(BtcChain, u32)>,
}

/// The coin-type number of `network` (0 mainnet, 1 testnet4).
#[must_use]
pub const fn coin_number(network: BtcNetwork) -> u32 {
    network.coin_number()
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// The signing payload (spec/08 §10), big-endian, `[ ]` only when the preceding flag is 1:
///
/// ```text
/// network_id u8 ‖ u32 len ‖ unsigned_tx (serialize(tx, false))
/// ‖ n_in u16 ‖ n_in × (value u64 ‖ chain u8 ‖ index u32)          (transaction input order)
/// ‖ has_change u8 ‖ [change_vout u32 ‖ change_index u32]
/// ‖ fee u64 ‖ planned_vsize u32 ‖ has_replaces u8 ‖ [replaces_txid 32 (internal order)]
/// ‖ fee_override_typed u8
/// ‖ [account block 19, every account but BIP84 account 0:
///    0x01 ‖ source u8 (1 HD, 2 imported, 3 EVM key) ‖ script_type u8
///    ‖ HD account u32 ‖ 0^12 | record id 16 | EVM account index u32 ‖ 0^12]
/// ‖ [account block 35 instead, an HD account of an added mnemonic (spec/02 §8.6):
///    0x02 ‖ 1 ‖ script_type u8 ‖ account u32 ‖ 0^12 ‖ mnemonic record id 16]
/// ```
///
/// The unsigned transaction carries the fixed P2SH-P2WPKH scriptSigs; the account block binds
/// the address type and key source (an imported key's identity is its public key, which several
/// types share).
#[must_use]
pub fn btc_payload(plan: &SendPlan) -> Vec<u8> {
    let unsigned = serialize(plan.tx(), false);
    let mut out = Vec::with_capacity(unsigned.len().saturating_add(64));
    out.push(plan.network().id());
    push_u32(&mut out, u32::try_from(unsigned.len()).unwrap_or(u32::MAX));
    out.extend_from_slice(&unsigned);
    let inputs = plan.inputs();
    out.extend_from_slice(
        &u16::try_from(inputs.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    for input in inputs {
        out.extend_from_slice(&input.value.get().to_be_bytes());
        out.push(u8::try_from(input.chain.index()).unwrap_or(u8::MAX));
        push_u32(&mut out, input.index);
    }
    match plan.change() {
        Some(change) => {
            out.push(1);
            push_u32(&mut out, change.vout);
            push_u32(&mut out, change.index);
        }
        None => out.push(0),
    }
    out.extend_from_slice(&plan.fee().get().to_be_bytes());
    push_u32(&mut out, plan.planned_vsize());
    match plan.replaces() {
        Some(txid) => {
            out.push(1);
            out.extend_from_slice(txid.as_bytes());
        }
        None => out.push(0),
    }
    out.push(u8::from(plan.fee_override_typed()));
    if let Some(block) = account_block(plan.account()) {
        if let Some(mnemonic) = plan.account().mnemonic() {
            // An added mnemonic's account: marker 2, then its record id.
            out.push(2);
            out.extend_from_slice(block.get(1..).unwrap_or_default());
            out.extend_from_slice(mnemonic.as_bytes());
        } else {
            out.extend_from_slice(&block);
        }
    }
    out
}

/// The structural header of a payload (used by `ApprovalStore::issue` to bind kind and chain).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BtcPayloadHeader {
    /// `network_id`.
    pub network: u8,
    /// `has_replaces` (a fee bump).
    pub has_replaces: bool,
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, count: usize) -> Option<&[u8]> {
        let end = self.at.checked_add(count)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn flag(&mut self) -> Option<bool> {
        match self.take(1)? {
            [0] => Some(false),
            [1] => Some(true),
            _ => None,
        }
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
}

/// Walks a payload's framing (lengths and flags, exact end); `None` when it is not a
/// well-formed `btc_payload`.
#[must_use]
pub fn payload_header(bytes: &[u8]) -> Option<BtcPayloadHeader> {
    let mut reader = Reader { bytes, at: 0 };
    let network = *reader.take(1)?.first()?;
    let tx_len = usize::try_from(reader.u32()?).ok()?;
    reader.take(tx_len)?;
    let inputs = usize::from(reader.u16()?);
    reader.take(inputs.checked_mul(13)?)?;
    if reader.flag()? {
        reader.take(8)?;
    }
    reader.take(12)?;
    let has_replaces = reader.flag()?;
    if has_replaces {
        reader.take(32)?;
    }
    reader.flag()?;
    if reader.at != bytes.len() {
        // The account block of a non-primary account: marker 1, source, type, 16 bytes; marker
        // 2 (an added mnemonic's HD account) adds the 16-byte record id.
        let block = reader.take(ACCOUNT_BLOCK_LEN)?;
        match block.first() {
            Some(1) => {}
            Some(2) if block.get(1) == Some(&1) => {
                reader.take(16)?;
            }
            _ => return None,
        }
    }
    (reader.at == bytes.len()).then_some(BtcPayloadHeader {
        network,
        has_replaces,
    })
}

/// Length of the payload account block (`1 ‖ source ‖ type ‖ 16 bytes`).
const ACCOUNT_BLOCK_LEN: usize = 19;

/// The account block of `account`, `None` for the primary (BIP84 account 0) whose payload keeps
/// the original layout: `0x01 ‖ source (1 HD, 2 imported, 3 EVM account key, 4 YubiKey address
/// key, 5 YubiKey EVM key) ‖ ScriptType code ‖ (HD: account u32 ‖ 12 zero bytes | imported:
/// record id 16 | EVM and YubiKey: the index u32 ‖ 12 zero bytes)`.
fn account_block(account: &BtcAccountKey) -> Option<[u8; ACCOUNT_BLOCK_LEN]> {
    let id = account.id();
    if id == BtcAccountId::PRIMARY {
        return None;
    }
    let mut out = [0_u8; ACCOUNT_BLOCK_LEN];
    let mut body = [0_u8; 16];
    let source = match id {
        BtcAccountId::Hd { account, .. } => {
            for (slot, byte) in body.iter_mut().zip(account.to_be_bytes()) {
                *slot = byte;
            }
            1
        }
        BtcAccountId::Imported { id } => {
            body = id;
            2
        }
        BtcAccountId::EvmShared { evm_index, .. } => {
            for (slot, byte) in body.iter_mut().zip(evm_index.to_be_bytes()) {
                *slot = byte;
            }
            3
        }
        BtcAccountId::Hardware { key, .. } => {
            for (slot, byte) in body.iter_mut().zip(key.index().to_be_bytes()) {
                *slot = byte;
            }
            key.source_code()
        }
    };
    for (slot, byte) in out.iter_mut().zip(
        [1, source, account.script_type().code()]
            .iter()
            .chain(body.iter()),
    ) {
        *slot = *byte;
    }
    Some(out)
}

/// The approval title: `[Bitcoin 메인넷] 보내기: 0.00120000 BTC` or
/// `[Bitcoin testnet4] 수수료 올리기` (English `[Bitcoin mainnet] Send: 0.00120000 BTC`,
/// `[Bitcoin testnet4] Bump fee`). The journal activity rebuilds the same text.
#[must_use]
pub fn btc_title(lang: Lang, network: BtcNetwork, fee_bump: bool, amount: Sats) -> String {
    let name = text::network_name(lang, network);
    if fee_bump {
        text::TITLE_FEE_BUMP.fill(lang, [name])
    } else {
        text::TITLE_SEND.fill(lang, [name, &format_btc(amount)])
    }
}

/// The warnings of a plan (spec/08 §10 table), in `lang`.
#[must_use]
pub fn plan_warnings(lang: Lang, plan: &SendPlan, facts: &BtcSendFacts) -> Vec<Warning> {
    let mut out = Vec::new();
    match plan.fee_check() {
        Some(check) if check.unoverridable => out.push(BtcWarning::FeeUnoverridable),
        Some(check) if check.over_cap && plan.fee_override_typed() => {
            out.push(BtcWarning::FeeCapOverridden);
        }
        Some(check) if check.over_cap => out.push(BtcWarning::FeeCapBlocked),
        Some(_) => {}
        None => out.push(BtcWarning::FeeUnoverridable),
    }
    if plan.fee_check().is_some_and(|check| check.ratio_high) {
        out.push(BtcWarning::FeeRatio);
    }
    if facts.first_time_recipient {
        out.push(BtcWarning::FirstTimeRecipient);
    }
    if plan.recipient_decreased() {
        out.push(BtcWarning::RecipientDecreased);
    }
    if plan.excluded_utxos() > 0 {
        out.push(BtcWarning::UtxosExcluded {
            count: plan.excluded_utxos(),
        });
    }
    if let Some((chain, index)) = facts.own_recipient {
        out.push(BtcWarning::OwnAddress {
            account: *plan.account(),
            network: plan.network(),
            chain,
            index,
        });
    }
    match plan.recipient() {
        super::ScriptKind::P2pkh(_) => out.push(BtcWarning::LegacyRecipient),
        super::ScriptKind::P2sh(_) | super::ScriptKind::P2wsh(_) => {
            out.push(BtcWarning::ScriptRecipient);
        }
        super::ScriptKind::P2wpkh(_) | super::ScriptKind::P2tr(_) => {}
    }
    out.into_iter()
        .map(|warning| warning.warning(lang))
        .collect()
}

/// `fee / amount` as a percentage with 2 decimals, rounded half up.
fn percent(fee: Sats, amount: Sats) -> String {
    let amount = u128::from(amount.get());
    let hundredths = u128::from(fee.get())
        .checked_mul(20_000)
        .and_then(|scaled| scaled.checked_add(amount))
        .and_then(|scaled| scaled.checked_div(amount.checked_mul(2)?));
    match hundredths {
        Some(value) => format!(
            "{}.{:02}",
            value.checked_div(100).unwrap_or(0),
            value.checked_rem(100).unwrap_or(0)
        ),
        None => "-".to_owned(),
    }
}

fn recipient_address(plan: &SendPlan) -> Result<String, DisplayError> {
    let kind = kind_from_script(&plan.recipient_script()).ok_or(DisplayError::InvalidText)?;
    Ok(encode_address(&kind, plan.network()))
}

fn change_text(lang: Lang, plan: &SendPlan) -> String {
    match plan.change() {
        Some(change) => {
            let account = plan.account();
            let (chain, index) = account.change_path(change.index);
            let place = if account.is_single() {
                account.address(plan.network(), chain, index).map_or_else(
                    |_| text::CHANGE_SAME_ADDRESS.get(lang).to_owned(),
                    |address| address.to_string(),
                )
            } else {
                text::path_text(lang, account, plan.network(), chain, index)
            };
            text::CHANGE_BACK.fill(lang, [&format_btc(change.value), &place])
        }
        None => text::CHANGE_NONE.fill(lang, [&format_sats_grouped(plan.change_folded().get())]),
    }
}

fn inputs_text(lang: Lang, plan: &SendPlan, facts: &BtcSendFacts) -> String {
    let total = plan.input_total().unwrap_or(Sats::MAX);
    let confirmations = facts.min_confirmations.map_or_else(
        || text::CONFIRMATIONS_UNKNOWN.get(lang).to_owned(),
        |count| text::CONFIRMATIONS.fill(lang, [&count.to_string()]),
    );
    text::INPUTS.fill(
        lang,
        [
            &plan.inputs().len().to_string(),
            &format_btc_and_sats(total),
            &confirmations,
        ],
    )
}

fn fee_text(lang: Lang, plan: &SendPlan) -> String {
    let vsize = plan.planned_vsize();
    let rate = rate_kvb(plan.fee(), u64::from(vsize)).map_or_else(
        || "-".to_owned(),
        |rate| FeeRate::from_sat_per_kvb(rate).to_string(),
    );
    let mut out = text::FEE.fill(
        lang,
        [
            &format_btc_and_sats(plan.fee()),
            &rate,
            &vsize.to_string(),
            &percent(plan.fee(), plan.amount()),
            &text::fee_source_text(lang, plan.fee_source()),
        ],
    );
    if plan.fee_override_typed() {
        out.push('\n');
        out.push_str(text::FEE_OVERRIDE.get(lang));
    }
    out
}

fn balance_text(lang: Lang, plan: &SendPlan, facts: &BtcSendFacts) -> String {
    let change = plan.change().map_or(Sats::ZERO, |change| change.value);
    let after = facts
        .verified_balance
        .checked_sub(plan.new_input_total())
        .and_then(|rest| rest.checked_add(change));
    let base = text::BALANCE_BASE.fill(lang, [&format_btc(facts.verified_balance)]);
    match after {
        Some(after) => format!("{} ({base})", format_btc_and_sats(after)),
        None => text::BALANCE_UNKNOWN.fill(lang, [&base]),
    }
}

fn replaces_text(lang: Lang, plan: &SendPlan) -> Option<String> {
    let bump = plan.bump()?;
    let delta = plan.fee().checked_sub(bump.old_fee).unwrap_or(Sats::ZERO);
    let recipient = if plan.recipient_decreased() {
        text::REPLACES_DECREASED.fill(
            lang,
            [
                &format_sats_grouped(bump.old_amount.get()),
                &format_sats_grouped(plan.amount().get()),
            ],
        )
    } else {
        text::REPLACES_SAME_RECIPIENT.get(lang).to_owned()
    };
    let mut out = text::REPLACES.fill(
        lang,
        [
            &bump.replaces.to_string(),
            &format_sats_grouped(bump.old_fee.get()),
            &format_sats_grouped(plan.fee().get()),
            &format_sats_grouped(delta.get()),
            &recipient,
        ],
    );
    if bump.min_applied {
        out.push('\n');
        out.push_str(text::REPLACES_BIP125_MIN.get(lang));
    }
    Some(out)
}

fn advanced_text(lang: Lang, plan: &SendPlan) -> String {
    let txid = if plan.txid_is_final() {
        plan.txid().to_string()
    } else {
        text::TXID_AFTER_SIGNING.get(lang).to_owned()
    };
    let lock_time = plan.lock_time().to_string();
    text::ADVANCED.fill(
        lang,
        [
            &BTC_TX_VERSION.to_string(),
            &lock_time,
            &lock_time,
            &format!("{BTC_SEQUENCE:08X}"),
            plan.account().script_type().technical(),
            &plan.planned_vsize().to_string(),
            &plan.planned_weight().to_string(),
            &txid,
        ],
    )
}

/// The approval account field: `Bitcoin 네이티브 세그윗 계정 0 (m/84'/0'/0')`, or for an imported
/// key `Bitcoin 가져온 키 · 레거시 (<address>)` (English `Bitcoin Native SegWit account 0 (…)`).
fn account_text(lang: Lang, account: &BtcAccountKey, network: BtcNetwork) -> String {
    let place = if account.is_single() {
        account
            .address(network, BtcChain::Receive, 0)
            .map_or_else(|_| "-".to_owned(), |address| address.to_string())
    } else {
        text::node_text(lang, account, network)
    };
    format!("Bitcoin {} ({place})", text::account_name(lang, account))
}

/// Builds the draft of a send or fee bump in `lang` (spec/08 §10, spec/14): origin `App`, chain
/// `Bitcoin` with the
/// network's pinned genesis, account = the account identity (`BtcAccountKey::identity`),
/// `Signer::FromPayload`, payload [`btc_payload`], `SimulationBinding::NotApplicable`.
///
/// # Errors
///
/// [`DisplayError`] (defensive: every string is built here; also when `account` is not the
/// plan's account).
pub fn build_btc_request(
    lang: Lang,
    id: ApprovalId,
    plan: &SendPlan,
    account: &BtcAccountKey,
    facts: &BtcSendFacts,
) -> Result<ApprovalDraft, DisplayError> {
    if plan.account() != account {
        return Err(DisplayError::InvalidText);
    }
    let network = plan.network();
    let total = plan
        .amount()
        .checked_add(plan.fee())
        .ok_or(DisplayError::InvalidText)?;
    let kind = plan.recipient();
    let mut fields = vec![
        DisplayField::new(FieldKey::ORIGIN, "", crate::approval::APP_ORIGIN.get(lang))?,
        DisplayField::new(FieldKey::NETWORK, "", text::network_banner(lang, network))?,
        DisplayField::new(FieldKey::ACCOUNT, "", account_text(lang, account, network))?,
        DisplayField::new(FieldKey::BTC_TO, "", recipient_address(plan)?)?,
        DisplayField::new(FieldKey::BTC_TYPE, "", text::type_label(lang, &kind))?,
        DisplayField::new(FieldKey::BTC_AMOUNT, "", format_btc_and_sats(plan.amount()))?,
        DisplayField::new(FieldKey::BTC_CHANGE, "", change_text(lang, plan))?,
        DisplayField::new(FieldKey::BTC_INPUTS, "", inputs_text(lang, plan, facts))?,
        DisplayField::new(FieldKey::BTC_FEE, "", fee_text(lang, plan))?,
        DisplayField::new(FieldKey::BTC_TOTAL, "", format_btc_and_sats(total))?,
        DisplayField::new(FieldKey::BTC_BALANCE, "", balance_text(lang, plan, facts))?,
    ];
    if let Some(value) = replaces_text(lang, plan) {
        fields.push(DisplayField::new(FieldKey::BTC_REPLACES, "", value)?);
    }
    fields.push(DisplayField::new(
        FieldKey::BTC_ADVANCED,
        "",
        advanced_text(lang, plan),
    )?);
    let display = ApprovalDisplay::new(
        lang,
        btc_title(lang, network, plan.bump().is_some(), plan.amount()),
        fields,
        plan_warnings(lang, plan, facts),
    )?;
    Ok(ApprovalDraft {
        id,
        origin: ApprovalOrigin::App,
        chain: ChainRef::Bitcoin {
            network: network.id(),
            genesis: network.genesis(),
        },
        account: AccountRef::Bitcoin(account.identity()),
        signer: Signer::FromPayload,
        kind: plan.kind(),
        payload: SigningPayload::Btc(btc_payload(plan)),
        display,
        simulation: SimulationBinding::NotApplicable,
    })
}
