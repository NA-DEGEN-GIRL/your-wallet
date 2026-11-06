//! The `HyperCore 전송` approval (kind `0x40`, spec/11 §6): network, action, recipient with the
//! app's address notes, token and amount, the fixed withdrawal fee, and the raw typed data under
//! the details. Every value is built here from the app-built [`HcAction`] (never from a dApp).

use super::{HcAction, HcKind, HcNetwork, HcPayload, HcToken, WITHDRAW_FEE_USDC};
use crate::approval::{
    APP_ORIGIN_TEXT, AccountRef, ApprovalDisplay, ApprovalDraft, ApprovalId, ApprovalKind,
    ApprovalOrigin, ChainRef, DisplayError, DisplayField, FieldKey, Signer, SigningPayload,
    SimulationBinding, Warning, escape_untrusted,
};
use crate::evm::address::Address;
use crate::evm::risk::{H01, H02, H03, H04, H05, sort_warnings, warning};
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
            HcKind::SendAsset => {
                text.push_str(
                    "\nHyperEVM 시스템 주소 — 토큰은 HyperEVM의 같은 주소(서명 계정)로 들어갑니다",
                );
                warnings.push(warning(H04, None));
            }
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
        HcPayload::UsdSend { amount, .. }
        | HcPayload::Withdraw { amount, .. }
        | HcPayload::UsdClassTransfer { amount, .. } => format!("{amount} USDC"),
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
