//! The `HyperCore 전송` approval (kind `0x40`, spec/11 §6): network, action, recipient with the
//! app's address notes, token and amount, the fixed withdrawal fee, and the raw typed data under
//! the details. Every value is built here from the app-built [`HcAction`] (never from a dApp).

use super::{
    HYPE_SYSTEM_ADDRESS, HcAction, HcKind, HcNetwork, HcPayload, HcToken, WITHDRAW_FEE_USDC,
    system_address_index,
};
use crate::approval::{
    APP_ORIGIN_TEXT, AccountRef, ApprovalDisplay, ApprovalDraft, ApprovalId, ApprovalKind,
    ApprovalOrigin, ChainRef, DisplayError, DisplayField, FieldKey, RuleId, Signer, SigningPayload,
    SimulationBinding, Warning, escape_untrusted,
};
use crate::evm::address::{Address, parse_address};
use crate::evm::eip712::TdNode;
use crate::evm::risk::{H01, H02, H03, H04, H05, H10, H11, H12, H13, H14, sort_warnings, warning};
use crate::vault::EvmKeySource;

/// What the app checked about the recipient (spec/04 §2.15 notes of the send form).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HcRecipient {
    /// Note lines shown under the address (book name, own account, look-alike, …).
    pub notes: Vec<String>,
    /// W-ADDR-3: similar to a known address (H03, High).
    pub look_alike: bool,
    /// Not in the address book nor an own account (H02).
    pub not_in_book: bool,
}

/// What the app checked for a dApp-requested Hyperliquid user-signed transfer (spec/11 §7): the
/// S-HC recipient check of its `destination` and the cached `spotMeta` of its network. Missing
/// facts fail closed (high risk).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HlSiteFacts {
    /// The S-HC recipient check of `destination` (`None` when it was not checked).
    pub recipient: Option<HcRecipient>,
    /// The cached `spotMeta` tokens of the action's `hyperliquidChain` (`None`: unavailable).
    pub spot_meta: Option<Vec<HcToken>>,
}

/// The verdict on a dApp-requested Hyperliquid transfer (spec/11 §7).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HlSiteCheck {
    /// Rules to add besides H01/H09 (H03, H04, H10–H14).
    pub rules: Vec<RuleId>,
    /// The parsed `destination`.
    pub destination: Option<Address>,
    /// `destination` is the system address of the (spotMeta-linked) token: a `HyperEVM` move.
    pub evm_move: bool,
    /// The `spotMeta` token matching `token` (name and tokenId).
    pub token: Option<HcToken>,
}

/// The `sendAsset` dex name of the spot balance (docs: `"spot"` is the spot balance, `""` the
/// default USDC perp dex). A `HyperEVM` move is spot → spot from the signing account itself
/// (`fromSubAccount` empty).
pub const SPOT_DEX: &str = "spot";

/// Checks a dApp-requested Hyperliquid transfer: the destination against own accounts, the
/// address book and look-alikes (the S-HC check), `withdraw3` to another address, system
/// addresses without a linked token or (`sendAsset`) not spot → spot from the signing account
/// itself, and `token` against `spotMeta`.
#[must_use]
pub fn site_transfer_check(
    kind: HcKind,
    root: &TdNode,
    account: &Address,
    facts: Option<&HlSiteFacts>,
) -> HlSiteCheck {
    let mut check = HlSiteCheck::default();
    let text = |name: &str| root.field(name).and_then(TdNode::string);
    if matches!(kind, HcKind::SpotSend | HcKind::SendAsset) {
        let spot = facts.and_then(|facts| facts.spot_meta.as_deref());
        check.token = text("token")
            .and_then(|wire| wire.rsplit_once(':'))
            .and_then(|(name, id)| {
                spot?
                    .iter()
                    .find(|token| token.token_id == id && token.name == name)
                    .cloned()
            });
        if check.token.is_none() {
            check.rules.push(H12);
        }
    }
    if kind == HcKind::UsdClassTransfer {
        return check;
    }
    let Some(destination) = text("destination").and_then(|text| parse_address(text).ok()) else {
        check.rules.push(H10);
        return check;
    };
    check.destination = Some(destination);
    let system = system_address_index(&destination).is_some() || destination == HYPE_SYSTEM_ADDRESS;
    if kind == HcKind::Withdraw {
        if destination != *account {
            check.rules.push(H11);
        }
        return check;
    }
    if system {
        let linked = matches!(kind, HcKind::SpotSend | HcKind::SendAsset)
            && check
                .token
                .as_ref()
                .is_some_and(|token| token.evm.is_some() && token.system_address() == destination);
        // `sendAsset` carries its own dex and sub-account fields: only spot → spot from the
        // signing account is the move H04 describes (a missing field fails closed).
        let spot_to_spot = kind != HcKind::SendAsset
            || (text("sourceDex") == Some(SPOT_DEX)
                && text("destinationDex") == Some(SPOT_DEX)
                && text("fromSubAccount") == Some(""));
        if !linked {
            check.rules.push(H13);
        } else if spot_to_spot {
            check.evm_move = true;
            check.rules.push(H04);
        } else {
            check.rules.push(H14);
        }
        return check;
    }
    if destination == *account {
        return check;
    }
    match facts.and_then(|facts| facts.recipient.as_ref()) {
        Some(recipient) if recipient.look_alike => check.rules.push(H03),
        Some(recipient) if !recipient.not_in_book => {}
        _ => check.rules.push(H10),
    }
    check
}

/// Inputs of [`build_hypercore_request`].
#[derive(Clone, Debug)]
pub struct HcApprovalInput<'a> {
    /// The action to sign.
    pub action: &'a HcAction,
    /// Signing account.
    pub account: Address,
    /// Key source.
    pub signer: EvmKeySource,
    /// The spot token of `spotSend`/`sendAsset` (from `spotMeta`).
    pub token: Option<&'a HcToken>,
    /// Recipient checks (ignored for `usdClassTransfer` and the `HyperEVM` move).
    pub recipient: HcRecipient,
}

/// Network field text.
#[must_use]
pub fn network_text(network: HcNetwork, signature_chain_id: u64) -> String {
    format!(
        "Hyperliquid {} (chainId {signature_chain_id}로 서명 · hyperliquidChain {})",
        network.label(),
        network.chain_name()
    )
}

fn token_text(token: Option<&HcToken>, wire: &str) -> String {
    token.map_or_else(
        || escape_untrusted(wire).text,
        |token| {
            format!(
                "{} (토큰 index {}, tokenId {}, 소수 {}자리)",
                escape_untrusted(&token.name).text,
                token.index,
                token.token_id,
                token.wei_decimals
            )
        },
    )
}

/// What Arbitrum receives for a `withdraw3` of `amount` USDC: the amount minus the fixed fee
/// (`0` when it does not cover the fee; the form refuses those).
#[must_use]
pub fn withdraw_arrival(amount: &str) -> String {
    let units = |text: &str| crate::evm::amount::parse_units(text, super::USD_DECIMALS).ok();
    match (units(amount), units(WITHDRAW_FEE_USDC)) {
        (Some(amount), Some(fee)) => amount.checked_sub(fee).map_or_else(
            || "0".to_owned(),
            |rest| super::wire_amount(&rest, super::USD_DECIMALS),
        ),
        _ => "?".to_owned(),
    }
}

fn push(fields: &mut Vec<DisplayField>, key: FieldKey, value: String) -> Result<(), DisplayError> {
    fields.push(DisplayField::new(key, "", value)?);
    Ok(())
}

/// Builds the `HyperCore 전송` draft (app origin, [`ChainRef::HyperCore`], no simulation).
///
/// # Errors
///
/// [`DisplayError`] (defensive).
#[expect(
    clippy::too_many_lines,
    reason = "one block per display field of spec/11 §6"
)]
pub fn build_hypercore_request(
    id: ApprovalId,
    input: &HcApprovalInput<'_>,
) -> Result<ApprovalDraft, DisplayError> {
    let action = input.action;
    let kind = action.kind();
    let mut fields = Vec::new();
    let mut warnings: Vec<Warning> = vec![warning(H01, None)];
    push(&mut fields, FieldKey::ORIGIN, APP_ORIGIN_TEXT.to_owned())?;
    push(
        &mut fields,
        FieldKey::NETWORK,
        network_text(action.network, action.signature_chain_id),
    )?;
    push(&mut fields, FieldKey::ACCOUNT, input.account.to_checksum())?;
    let action_text = match &action.payload {
        HcPayload::UsdClassTransfer { to_perp, .. } => format!(
            "{}\n방향: {}",
            kind.korean(),
            if *to_perp {
                "현물(spot) → 선물(perp)"
            } else {
                "선물(perp) → 현물(spot)"
            }
        ),
        _ => kind.korean().to_owned(),
    };
    push(
        &mut fields,
        FieldKey::HC_ACTION,
        format!("{action_text}\n(type {})", kind.wire_type()),
    )?;
    if let Some(destination) = action.destination() {
        let mut text = destination.to_checksum();
        match kind {
            // The move note only when the destination is the system address of the spotMeta
            // token linked to HyperEVM and the move is spot → spot; anything else is high risk
            // (H13, H14).
            HcKind::SendAsset
                if !input.token.is_some_and(|token| {
                    token.evm.is_some() && token.system_address() == destination
                }) =>
            {
                warnings.push(warning(H13, None));
            }
            HcKind::SendAsset
                if matches!(
                    &action.payload,
                    HcPayload::SendAsset { source_dex, destination_dex, .. }
                        if source_dex == SPOT_DEX && destination_dex == SPOT_DEX
                ) =>
            {
                text.push_str(
                    "\nHyperEVM 시스템 주소 — 토큰은 HyperEVM의 같은 주소(서명 계정)로 들어갑니다",
                );
                warnings.push(warning(H04, None));
            }
            HcKind::SendAsset => warnings.push(warning(H14, None)),
            HcKind::Withdraw => {
                text.push_str("\nArbitrum One의 이 주소로 USDC가 들어갑니다");
            }
            _ => {}
        }
        if kind != HcKind::SendAsset {
            for note in &input.recipient.notes {
                text.push('\n');
                text.push_str(&escape_untrusted(note).text);
            }
            if input.recipient.look_alike {
                warnings.push(warning(H03, None));
            } else if input.recipient.not_in_book {
                warnings.push(warning(H02, None));
            }
        }
        if destination == input.account && kind != HcKind::SendAsset && kind != HcKind::Withdraw {
            text.push_str("\n보내는 계정과 같은 주소입니다");
        }
        push(&mut fields, FieldKey::HC_TO, text)?;
    }
    let amount = match &action.payload {
        HcPayload::SpotSend { token, amount, .. } | HcPayload::SendAsset { token, amount, .. } => {
            let symbol = input.token.map_or_else(
                || "?".to_owned(),
                |token| escape_untrusted(&token.name).text,
            );
            format!("{amount} {symbol}\n{}", token_text(input.token, token))
        }
        HcPayload::Withdraw { amount, .. } => format!(
            "{amount} USDC\nArbitrum 도착 = 금액 − {WITHDRAW_FEE_USDC} USDC = {} USDC",
            withdraw_arrival(amount)
        ),
        HcPayload::UsdSend { amount, .. } | HcPayload::UsdClassTransfer { amount, .. } => {
            format!("{amount} USDC")
        }
    };
    push(&mut fields, FieldKey::HC_AMOUNT, amount)?;
    let fee = match kind {
        HcKind::Withdraw => {
            warnings.push(warning(H05, None));
            format!("{WITHDRAW_FEE_USDC} USDC (고정 출금 수수료, HyperCore에서 차감)")
        }
        HcKind::SendAsset => "HyperCore에서 HYPE로 HyperEVM 가스(200k gas)를 냅니다".to_owned(),
        _ => "없음 (HyperCore 사용자 서명 작업)".to_owned(),
    };
    push(&mut fields, FieldKey::HC_FEE, fee)?;
    push(
        &mut fields,
        FieldKey::HC_NONCE,
        format!("{} (unix ms, 서명 시각)", action.nonce),
    )?;
    push(
        &mut fields,
        FieldKey::HC_TYPED,
        String::from_utf8_lossy(&yw_json::to_vec(&action.typed_data_json())).into_owned(),
    )?;
    sort_warnings(&mut warnings);
    let title = format!(
        "[{}] HyperCore 전송: {}",
        action.network.label(),
        kind.korean()
    );
    let display = ApprovalDisplay::new(title, fields, warnings)?;
    Ok(ApprovalDraft {
        id,
        origin: ApprovalOrigin::App,
        chain: ChainRef::HyperCore {
            network: action.network.code(),
            signature_chain_id: action.signature_chain_id,
        },
        account: AccountRef::Evm(input.account),
        signer: Signer::Evm(input.signer),
        kind: ApprovalKind::HyperCoreAction,
        payload: SigningPayload::HyperCore(Box::new(action.clone())),
        display,
        simulation: SimulationBinding::NotApplicable,
    })
}
