//! The main window's control id ↔ [`Press`] table (spec/04 §2.1, spec/15 §11.4 S3). The window
//! reports a click as a control id (`WM_COMMAND`); `App::on_command` turns it into a
//! `Cmd::Press` with [`press_of`], and [`id_of`] gives the id back where the Windows shell still
//! keys state by id (the copy mark `App::command`, an open drop-down).
//!
//! 2026-11-18 (S3 B2): created. Enter and Esc map to `Press::Enter`/`Press::Back`; every other id
//! is `Press::Legacy(id)` until its handler family is converted (S3 C1–C12), and `Legacy` goes in
//! S3 D3.
//!
//! 2026-11-18 (S3 B5): the edit ids ↔ `EditField` (58 plain edits) and `CredField` (7 masked
//! credential edits), the credential edits each press reads ([`creds_for`], plan §3.4) and
//! [`capture`], which reads them into a `PressInput` when the press happens.

use yw_core::secret::Zeroizing;
use yw_engine::cmd::Press;
use yw_engine::form::{CredField, CredUnits, EditField, PressInput};

use crate::ui::main_window::ControlSet;
use crate::ui::{screens, screens_evm, screens_llm};

/// The command id `IsDialogMessageW` sends for Enter (no control uses it, `ui::command_ids`).
pub const IDOK: u16 = 1;
/// The one it sends for Esc.
pub const IDCANCEL: u16 = 2;

/// The press a control id stands for.
#[must_use]
pub const fn press_of(id: u16) -> Press {
    match id {
        IDOK => Press::Enter,
        IDCANCEL => Press::Back,
        other => Press::Legacy(other),
    }
}

/// The control id of a press (the inverse of [`press_of`]).
#[must_use]
pub const fn id_of(press: Press) -> u16 {
    match press {
        Press::Enter => IDOK,
        Press::Back => IDCANCEL,
        Press::Legacy(id) => id,
    }
}

/// The 58 plain edits and their control ids (S3 B5).
const FIELDS: [(EditField, u16); 58] = {
    use crate::ui::{
        screens_book as book, screens_btc as btc, screens_evm as evm, screens_explorer as explorer,
        screens_hypercore as hc, screens_llm as llm, screens_mnemonics as mn,
        screens_reset as reset, screens_sol as sol, screens_walletconnect as wc,
        screens_yubikey as yk, screens_zec as zec,
    };
    [
        (EditField::CoreRename, screens::ids::RENAME_EDIT),
        (EditField::CoreAutoLock, screens::ids::AUTOLOCK_EDIT),
        (EditField::BookAddress, book::ids::ADDR_EDIT),
        (EditField::BookLabel, book::ids::LABEL_EDIT),
        (EditField::BookPromptLabel, book::ids::PROMPT_LABEL_EDIT),
        (EditField::BtcSendTo, btc::ids::SEND_TO_EDIT),
        (EditField::BtcSendAmount, btc::ids::SEND_AMOUNT_EDIT),
        (EditField::BtcFeeManual, btc::ids::FEE_MANUAL_EDIT),
        (EditField::BtcTypedFee, btc::ids::TYPED_FEE_EDIT),
        (EditField::BtcBumpManual, btc::ids::BUMP_MANUAL_EDIT),
        (EditField::BtcBumpTyped, btc::ids::BUMP_TYPED_EDIT),
        (EditField::BtcRename, btc::ids::RENAME_EDIT),
        (EditField::BtcEsploraMainnet, btc::ids::ESPLORA_MAINNET_EDIT),
        (
            EditField::BtcEsploraTestnet4,
            btc::ids::ESPLORA_TESTNET4_EDIT,
        ),
        (EditField::EvmSendTo, evm::ids::SEND_TO_EDIT),
        (EditField::EvmSendAmount, evm::ids::SEND_AMOUNT_EDIT),
        (EditField::EvmTokenAddress, evm::ids::TOKEN_ADDR_EDIT),
        (EditField::EvmTokenLabel, evm::ids::TOKEN_LABEL_EDIT),
        (EditField::EvmChainId, evm::ids::CHAIN_ID_EDIT),
        (EditField::EvmChainName, evm::ids::CHAIN_NAME_EDIT),
        (EditField::EvmChainSymbol, evm::ids::CHAIN_SYMBOL_EDIT),
        (EditField::EvmChainDecimals, evm::ids::CHAIN_DECIMALS_EDIT),
        (EditField::EvmChainExplorer, evm::ids::CHAIN_EXPLORER_EDIT),
        (EditField::EvmCapFee, evm::ids::CAPS_FEE_EDIT),
        (EditField::EvmCapTip, evm::ids::CAPS_TIP_EDIT),
        (EditField::EvmCapTotal, evm::ids::CAPS_TOTAL_EDIT),
        (EditField::ExplorerTx, explorer::ids::EDIT_TX),
        (EditField::ExplorerAddress, explorer::ids::EDIT_ADDRESS),
        (EditField::HcTo, hc::ids::TO_EDIT),
        (EditField::HcAmount, hc::ids::AMOUNT_EDIT),
        (EditField::HcApi, hc::ids::API_EDIT),
        (EditField::LlmEndpoint, llm::ids::ENDPOINT_EDIT),
        (EditField::LlmModel, llm::ids::MODEL_EDIT),
        (EditField::LlmMaxTokens, llm::ids::MAX_TOKENS_EDIT),
        (EditField::MnRemoveTyped, mn::ids::REMOVE_TYPED_EDIT),
        (EditField::MnRename, mn::ids::RENAME_EDIT),
        (EditField::ResetPhrase, reset::ids::RESET_PHRASE),
        (EditField::SolSendTo, sol::ids::SEND_TO_EDIT),
        (EditField::SolSendAmount, sol::ids::SEND_AMOUNT_EDIT),
        (EditField::SolFeeCap, sol::ids::FEE_CAP_EDIT),
        (EditField::SolCuPrice, sol::ids::CU_PRICE_EDIT),
        (EditField::SolRename, sol::ids::RENAME_EDIT),
        (EditField::WcUri, wc::ids::URI_EDIT),
        (EditField::WcFile, wc::ids::FILE_EDIT),
        (EditField::WcProject, wc::ids::PROJECT_EDIT),
        (EditField::YkSigIndex, yk::ids::SIG_INDEX_EDIT),
        (EditField::YkAutIndex, yk::ids::AUT_INDEX_EDIT),
        (EditField::YkSolCount, yk::ids::SOL_COUNT_EDIT),
        (EditField::YkSolStart, yk::ids::SOL_START_EDIT),
        (EditField::YkOverwrite, yk::ids::OVERWRITE_EDIT),
        (EditField::YkCardName, yk::ids::CARD_NAME_EDIT),
        (EditField::YkReslotSigIndex, yk::ids::RESLOT_SIG_INDEX_EDIT),
        (EditField::YkReslotAutIndex, yk::ids::RESLOT_AUT_INDEX_EDIT),
        (EditField::YkClearConfirm, yk::ids::CLEAR_CONFIRM_EDIT),
        (EditField::YkReslotLoss, yk::ids::RESLOT_LOSS_EDIT),
        (EditField::YkClearLoss, yk::ids::CLEAR_LOSS_EDIT),
        (EditField::ZecSendTo, zec::ids::SEND_TO_EDIT),
        (EditField::ZecSendAmount, zec::ids::SEND_AMOUNT_EDIT),
    ]
};

/// The 7 masked credential edits and their control ids (S3 B5).
const CREDS: [(CredField, u16); 7] = [
    (CredField::QnName, screens::ids::QN_NAME_EDIT),
    (CredField::QnToken, screens::ids::QN_TOKEN_EDIT),
    (CredField::AlchemyKey, screens::ids::ALCHEMY_KEY_EDIT),
    (CredField::RpcReplace, screens::ids::REPLACE_EDIT),
    (CredField::DoneQn, screens::ids::DONE_QN_EDIT),
    (CredField::ChainRpc, screens_evm::ids::CHAIN_RPC_EDIT),
    (CredField::LlmKey, screens_llm::ids::KEY_EDIT),
];

/// The plain edit control `id` is, if any.
#[must_use]
pub fn field_of(id: u16) -> Option<EditField> {
    FIELDS
        .iter()
        .find(|(_, known)| *known == id)
        .map(|(field, _)| *field)
}

/// The control id of plain edit `field`.
#[must_use]
pub fn edit_id_of(field: EditField) -> u16 {
    FIELDS
        .iter()
        .find(|(known, _)| *known == field)
        .map_or(0, |(_, id)| *id)
}

/// The credential edit control `id` is, if any.
#[must_use]
pub fn cred_of(id: u16) -> Option<CredField> {
    CREDS
        .iter()
        .find(|(_, known)| *known == id)
        .map(|(field, _)| *field)
}

/// The control id of credential edit `field`.
#[must_use]
pub fn cred_id_of(field: CredField) -> u16 {
    CREDS
        .iter()
        .find(|(known, _)| *known == field)
        .map_or(0, |(_, id)| *id)
}

/// The credential edits the handler of press `id` reads (plan §3.4); `on_command` captures each
/// of them with the press. A network row's `테스트` and the S10 cards' `테스트` read the open
/// `교체` field only when it is that network's (the units are wiped unread otherwise).
#[must_use]
pub fn creds_for(id: u16) -> &'static [CredField] {
    use screens::ids;
    const TEMPLATE: &[CredField] = &[CredField::QnName, CredField::QnToken, CredField::AlchemyKey];
    const REPLACE: &[CredField] = &[CredField::RpcReplace];
    match id {
        ids::TPL_SAVE | ids::GENERATE => TEMPLATE,
        ids::REPLACE_SAVE | ids::EVM_RPC_TEST | ids::SOL_RPC_TEST => REPLACE,
        ids::DONE_CONNECT => &[CredField::DoneQn],
        screens_evm::ids::CHAIN_SAVE => &[CredField::ChainRpc],
        screens_llm::ids::KEY_SAVE => &[CredField::LlmKey],
        _ if id
            .checked_sub(ids::ROW_BASE)
            .is_some_and(|offset| offset < ids::ROW_SPAN && offset % 3 == 1) =>
        {
            REPLACE
        }
        _ => &[],
    }
}

/// The press input of control `id` (Windows): the units of every credential edit
/// [`creds_for`] lists, read now into wiped buffers; `Absent` when that edit does not exist.
#[must_use]
pub fn capture(id: u16, controls: &ControlSet) -> PressInput {
    let creds = creds_for(id)
        .iter()
        .map(|&field| {
            let units = match controls.text_wiping(cred_id_of(field), field.cap()) {
                Some(read) => {
                    // Exact capacity: the units are never moved by a reallocation.
                    let mut units = Zeroizing::new(Vec::with_capacity(read.len()));
                    units.extend_from_slice(read.as_slice());
                    CredUnits::Units(units)
                }
                None => CredUnits::Absent,
            };
            (field, units)
        })
        .collect();
    PressInput::new(creds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::command_ids::{fixed, ranges};
    use crate::ui::screens_reset;

    /// Every id the main window can send: the fixed ids and every id of every indexed range up
    /// to its documented maximum.
    fn every_id() -> Vec<u16> {
        let mut ids: Vec<u16> = fixed()
            .into_iter()
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect();
        for range in ranges() {
            let rows = u32::try_from(range.max_rows).unwrap_or(u32::MAX);
            let used = (rows * u32::from(range.stride)).min(u32::from(range.span));
            for offset in 0..used {
                ids.push(u16::try_from(u32::from(range.base) + offset).unwrap());
            }
        }
        ids
    }

    /// Table test (1): the table is injective and round-trips every id.
    #[test]
    fn every_id_round_trips() {
        let ids = every_id();
        assert!(ids.len() > 1_000, "{}", ids.len());
        for id in ids {
            assert!(id != IDOK && id != IDCANCEL, "{id} is Enter or Esc");
            assert_eq!(id_of(press_of(id)), id, "{id}");
        }
        assert_eq!(press_of(IDOK), Press::Enter);
        assert_eq!(press_of(IDCANCEL), Press::Back);
        assert_eq!(id_of(Press::Enter), IDOK);
        assert_eq!(id_of(Press::Back), IDCANCEL);
    }

    /// Table test (6): S22's 2 s hold area is painted, not a control; it never becomes a family
    /// press that a click could post.
    #[test]
    fn reset_hold_stays_unpressable() {
        let hold = screens_reset::ids::RESET_HOLD;
        assert_eq!(press_of(hold), Press::Legacy(hold));
    }

    /// Table test (3): the 65 edit ids are 58 plain fields and 7 credential fields, each a
    /// bijection with its enum, none in both, all of them fixed ids of the main window.
    #[test]
    fn edit_ids_map_one_to_one() {
        let fixed_ids: Vec<u16> = fixed()
            .into_iter()
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect();
        let mut seen = Vec::new();
        for field in EditField::ALL {
            let id = edit_id_of(field);
            assert!(fixed_ids.contains(&id), "{field:?} {id}");
            assert_eq!(field_of(id), Some(field), "{id}");
            assert_eq!(cred_of(id), None, "{id}");
            assert!(!seen.contains(&id), "{id} twice");
            seen.push(id);
        }
        for field in CredField::ALL {
            let id = cred_id_of(field);
            assert!(fixed_ids.contains(&id), "{field:?} {id}");
            assert_eq!(cred_of(id), Some(field), "{id}");
            assert_eq!(field_of(id), None, "{id}");
            assert!(!seen.contains(&id), "{id} twice");
            seen.push(id);
        }
        assert_eq!(seen.len(), 65);
        // No other id is an edit field.
        for id in every_id() {
            assert_eq!(
                field_of(id).is_some() || cred_of(id).is_some(),
                seen.contains(&id)
            );
        }
    }

    /// Table test (8), the static half: exactly these presses capture credential edits (the
    /// census and `credential_capture_covers_every_read` prove the reads).
    #[test]
    fn creds_for_lists_the_credential_presses() {
        use crate::ui::screens::ids;
        let template = [CredField::QnName, CredField::QnToken, CredField::AlchemyKey];
        let mut listed = Vec::new();
        for id in every_id() {
            let creds = creds_for(id);
            if !creds.is_empty() {
                listed.push(id);
            }
            match id {
                ids::TPL_SAVE | ids::GENERATE => assert_eq!(creds, template),
                ids::DONE_CONNECT => assert_eq!(creds, [CredField::DoneQn]),
                screens_evm::ids::CHAIN_SAVE => assert_eq!(creds, [CredField::ChainRpc]),
                screens_llm::ids::KEY_SAVE => assert_eq!(creds, [CredField::LlmKey]),
                _ if !creds.is_empty() => assert_eq!(creds, [CredField::RpcReplace], "{id}"),
                _ => {}
            }
        }
        let row_tests = every_id()
            .into_iter()
            .filter(|id| {
                id.checked_sub(ids::ROW_BASE)
                    .is_some_and(|offset| offset < ids::ROW_SPAN && offset % 3 == 1)
            })
            .count();
        assert!(row_tests > 0);
        assert_eq!(listed.len(), 8 + row_tests);
        let rows = ids::ROW_SPAN / 3;
        for row in 0..rows {
            assert_eq!(creds_for(ids::ROW_BASE + 3 * row), [] as [CredField; 0]);
            assert_eq!(
                creds_for(ids::ROW_BASE + 3 * row + 1),
                [CredField::RpcReplace]
            );
            assert_eq!(creds_for(ids::ROW_BASE + 3 * row + 2), [] as [CredField; 0]);
        }
        assert!(creds_for(IDOK).is_empty() && creds_for(IDCANCEL).is_empty());
    }

    /// `capture` gives every listed field an entry — its units, or `Absent` when the edit does
    /// not exist — and nothing else; a plain edit's text is never captured.
    #[test]
    fn capture_holds_exactly_the_listed_fields() {
        use crate::ui::screens::ids;
        let controls = ControlSet::default();
        controls.type_text(ids::QN_NAME_EDIT, "node-name");
        controls.type_text(ids::QN_TOKEN_EDIT, "");
        controls.type_text(screens_llm::ids::ENDPOINT_EDIT, "https://example.test/");
        let mut input = capture(ids::TPL_SAVE, &controls);
        let shown = format!("{input:?}");
        assert!(
            shown.starts_with(
                "PressInput { creds: [(QnName, Units(9)), (QnToken, Units(0)), (AlchemyKey, \
                 Absent)]"
            ),
            "{shown}"
        );
        assert!(!shown.contains("node"), "{shown}");
        let units: Vec<u16> = "node-name".encode_utf16().collect();
        assert_eq!(input.take(CredField::QnName).as_slice(), units.as_slice());
        assert!(input.take(CredField::AlchemyKey).is_empty());
        #[cfg(debug_assertions)]
        assert_eq!(input.misses(), 0);
        // A plain press captures nothing; the credential cap is the edit's.
        let mut plain = capture(screens_llm::ids::SAVE, &controls);
        assert!(format!("{plain:?}").starts_with("PressInput { creds: []"));
        assert!(plain.take(CredField::LlmKey).is_empty());
        #[cfg(debug_assertions)]
        assert_eq!(plain.misses(), 1);
        controls.type_text(screens_llm::ids::KEY_EDIT, &"k".repeat(1_100));
        let mut key = capture(screens_llm::ids::KEY_SAVE, &controls);
        assert_eq!(key.take(CredField::LlmKey).len(), CredField::LlmKey.cap());
    }

    /// `form_snapshot` reads every plain edit that exists, at its cap, and never a credential
    /// edit.
    #[test]
    fn form_snapshot_reads_plain_edits_only() {
        let controls = ControlSet::default();
        for field in EditField::ALL {
            controls.type_text(edit_id_of(field), &"9".repeat(field.cap() + 3));
        }
        for field in CredField::ALL {
            controls.type_text(cred_id_of(field), "secret-value");
        }
        let snapshot = controls.form_snapshot();
        assert_eq!(snapshot.0.len(), 58);
        for (field, text) in &snapshot.0 {
            assert_eq!(text.as_str(), "9".repeat(field.cap()), "{field:?}");
            assert_eq!(
                controls.text(edit_id_of(*field), field.cap()).as_deref(),
                Some(text.as_str())
            );
        }
        assert!(!format!("{snapshot:?}").contains("secret"));
        assert!(ControlSet::default().form_snapshot().0.is_empty());
    }
}
