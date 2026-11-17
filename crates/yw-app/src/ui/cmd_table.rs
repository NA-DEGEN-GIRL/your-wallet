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
//!
//! 2026-11-18 (S3 C1): the received-history, hidden-account, side-file and drop-down/recipient
//! ids are their families' presses (each module's `ids::press_of`/`ids::id_of`); [`press_of`]
//! reads a check box's state into its press (the box is never read again by the handler).
//! S3 C2: S13's sites and `WalletConnect` panel. S3 C3: the block-explorer card and links and
//! the AI-explanation settings. S3 C4: the address book. S3 C5: S22 and T-WAIT-STALLED, S23,
//! the imported-key screens and the `rpc.json` import card. S3 C6: the recovery phrases. S3 C7:
//! `HyperCore` and Zcash.

use yw_core::secret::Zeroizing;
use yw_engine::cmd::Press;
use yw_engine::form::{CredField, CredUnits, EditField, PressInput};

use crate::ui::main_window::ControlSet;
use crate::ui::{
    screens, screens_book, screens_evm, screens_explorer, screens_hypercore, screens_keys,
    screens_links, screens_llm, screens_mnemonics, screens_received, screens_reset, screens_sites,
    screens_walletconnect, screens_zec,
};
use crate::{app_hidden, app_rpc_import, app_sidecar};

/// The command id `IsDialogMessageW` sends for Enter (no control uses it, `ui::command_ids`).
pub const IDOK: u16 = 1;
/// The one it sends for Esc.
pub const IDCANCEL: u16 = 2;

/// The press a control id stands for, with the state of its check box when it is one
/// (`controls.checked(id)` now).
#[must_use]
pub fn press_of(id: u16, controls: &ControlSet) -> Press {
    match id {
        IDOK => Press::Enter,
        IDCANCEL => Press::Back,
        other => screens_received::ids::press_of(other, controls)
            .map(Press::Received)
            .or_else(|| app_hidden::ids::press_of(other).map(Press::Hidden))
            .or_else(|| app_sidecar::ids::press_of(other, controls).map(Press::Sidecar))
            .or_else(|| screens_links::ids::press_of(other).map(Press::Links))
            .or_else(|| screens_sites::ids::press_of(other).map(Press::Sites))
            .or_else(|| screens_llm::ids::press_of(other, controls).map(Press::Llm))
            .or_else(|| screens_explorer::ids::press_of(other).map(Press::Explorer))
            .or_else(|| screens_walletconnect::ids::press_of(other).map(Press::Wc))
            .or_else(|| screens_book::ids::press_of(other, controls).map(Press::Book))
            .or_else(|| screens_reset::ids::reset_press_of(other, controls).map(Press::Reset))
            .or_else(|| screens_reset::ids::ext_press_of(other).map(Press::Ext))
            .or_else(|| screens_keys::ids::press_of(other).map(Press::Keys))
            .or_else(|| app_rpc_import::ids::press_of(other).map(Press::RpcImport))
            .or_else(|| screens_mnemonics::ids::press_of(other).map(Press::Mn))
            .or_else(|| screens_hypercore::ids::press_of(other).map(Press::Hc))
            .or_else(|| screens_zec::ids::press_of(other).map(Press::Zec))
            .unwrap_or(Press::Legacy(other)),
    }
}

/// The control id of a press (the inverse of [`press_of`]; a check box's state is not part of
/// it).
#[must_use]
pub const fn id_of(press: Press) -> u16 {
    match press {
        Press::Enter => IDOK,
        Press::Back => IDCANCEL,
        Press::Received(press) => screens_received::ids::id_of(press),
        Press::Hidden(press) => app_hidden::ids::id_of(press),
        Press::Sidecar(press) => app_sidecar::ids::id_of(press),
        Press::Links(press) => screens_links::ids::id_of(press),
        Press::Sites(press) => screens_sites::ids::id_of(press),
        Press::Llm(press) => screens_llm::ids::id_of(press),
        Press::Explorer(press) => screens_explorer::ids::id_of(press),
        Press::Wc(press) => screens_walletconnect::ids::id_of(press),
        Press::Book(press) => screens_book::ids::id_of(press),
        Press::Reset(press) => screens_reset::ids::reset_id_of(press),
        Press::Ext(press) => screens_reset::ids::ext_id_of(press),
        Press::Keys(press) => screens_keys::ids::id_of(press),
        Press::RpcImport(press) => app_rpc_import::ids::id_of(press),
        Press::Mn(press) => screens_mnemonics::ids::id_of(press),
        Press::Hc(press) => screens_hypercore::ids::id_of(press),
        Press::Zec(press) => screens_zec::ids::id_of(press),
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
        let controls = ControlSet::default();
        for id in ids {
            assert!(id != IDOK && id != IDCANCEL, "{id} is Enter or Esc");
            assert_eq!(id_of(press_of(id, &controls)), id, "{id}");
        }
        assert_eq!(press_of(IDOK, &controls), Press::Enter);
        assert_eq!(press_of(IDCANCEL, &controls), Press::Back);
        assert_eq!(id_of(Press::Enter), IDOK);
        assert_eq!(id_of(Press::Back), IDCANCEL);
    }

    /// Table test (6): S22's 2 s hold area is painted, not a control; it never becomes a family
    /// press that a click could post.
    #[test]
    fn reset_hold_stays_unpressable() {
        let hold = screens_reset::ids::RESET_HOLD;
        assert_eq!(press_of(hold, &ControlSet::default()), Press::Legacy(hold));
    }

    /// Table test (4) (S3 C1): for every id that is a family's press, the receive gate and the
    /// received-history observer `App::on_press` applies before the family handler are exactly
    /// the ones the legacy chain applied to that id (`screens::RECEIVE_IDS`,
    /// `app_received::refresh_chain`).
    #[test]
    fn family_presses_keep_the_gate_and_the_observer() {
        let controls = ControlSet::default();
        let mut families = 0;
        for id in every_id() {
            let press = press_of(id, &controls);
            if matches!(press, Press::Legacy(_) | Press::Enter | Press::Back) {
                continue;
            }
            families += 1;
            assert_eq!(
                press.is_receive_gated(),
                screens::RECEIVE_IDS.contains(&id),
                "{id}"
            );
            assert_eq!(
                press.refresh_chain(),
                crate::app_received::refresh_chain(id),
                "{id}"
            );
        }
        assert!(families > 0);
    }

    /// The families converted in S3 C1 claim exactly the ids their handlers claimed before
    /// (the id ranges below); a check box carries its state; nothing else in the map is theirs.
    #[test]
    fn c1_families_map_their_ids() {
        use yw_engine::cmd::{HiddenPress, LinksPress, ReceivedPress, Row, SidecarPress};
        use yw_engine::received::RecvChain;
        let controls = ControlSet::default();
        let family = |id: u16| {
            !matches!(
                press_of(id, &controls),
                Press::Legacy(_) | Press::Enter | Press::Back
            )
        };
        // Every id of the four families' blocks (ui::command_ids), and the gaps that stay legacy.
        for id in 16_100..16_590 {
            let hidden = id == 16_100
                || (16_110..16_175).contains(&id)
                || id == 16_200
                || id == 16_201
                || (16_210..16_590).contains(&id);
            assert_eq!(family(id), hidden, "{id}");
        }
        for id in 16_600..16_610 {
            assert_eq!(family(id), id < 16_604, "{id}");
        }
        for id in 17_800..18_400 {
            assert_eq!(family(id), !(17_810..17_900).contains(&id), "{id}");
        }
        for id in 18_400..18_660 {
            let links = !(18_404..18_410).contains(&id) && !(18_524..18_530).contains(&id);
            assert_eq!(family(id), links, "{id}");
        }
        assert_eq!(
            press_of(app_hidden::ids::BTC_ROW_BASE + 64, &controls),
            Press::Hidden(HiddenPress::BtcUnhide(Row(64)))
        );
        assert_eq!(
            press_of(screens_links::ids::ZEC_TO_BASE + 79, &controls),
            Press::Links(LinksPress::ZecTo(Row(79)))
        );
        assert_eq!(
            press_of(screens_received::ids::ROW_BASE + 499, &controls),
            Press::Received(ReceivedPress::OpenExplorer(RecvChain::Zec, Row(49)))
        );
        // A check box's state travels with the press.
        let toggle = screens_received::ids::toggle(RecvChain::Btc);
        assert_eq!(
            press_of(toggle, &controls),
            Press::Received(ReceivedPress::Toggle {
                chain: RecvChain::Btc,
                checked: None
            })
        );
        controls.type_check(toggle, true);
        controls.type_check(app_sidecar::ids::RESET_ACK, false);
        assert_eq!(
            press_of(toggle, &controls),
            Press::Received(ReceivedPress::Toggle {
                chain: RecvChain::Btc,
                checked: Some(true)
            })
        );
        assert_eq!(
            press_of(app_sidecar::ids::RESET_ACK, &controls),
            Press::Sidecar(SidecarPress::ResetAck(Some(false)))
        );
        assert_eq!(id_of(press_of(toggle, &controls)), toggle);
    }

    /// S3 C2: S13 and the `WalletConnect` panel claim exactly the ids their handlers claimed
    /// before; the panel's three edits are fields, not presses.
    #[test]
    fn c2_families_map_their_ids() {
        use yw_engine::cmd::{Row, SitesPress, WcPress};
        let controls = ControlSet::default();
        let family = |id: u16| {
            !matches!(
                press_of(id, &controls),
                Press::Legacy(_) | Press::Enter | Press::Back
            )
        };
        for id in 6_700..6_966 {
            assert_eq!(family(id), !(6_704..6_710).contains(&id), "{id}");
        }
        for id in 16_000..16_100 {
            let edit = [
                screens_walletconnect::ids::URI_EDIT,
                screens_walletconnect::ids::FILE_EDIT,
                screens_walletconnect::ids::PROJECT_EDIT,
            ]
            .contains(&id);
            let wc = !edit && !(16_012..16_020).contains(&id) && id < 16_084;
            assert_eq!(family(id), wc, "{id}");
        }
        assert_eq!(
            press_of(screens_sites::ids::SITE_ROW_BASE + 255, &controls),
            Press::Sites(SitesPress::Disconnect(Row(255)))
        );
        assert_eq!(
            press_of(screens_walletconnect::ids::ROW_BASE + 63, &controls),
            Press::Wc(WcPress::Disconnect(Row(63)))
        );
    }

    /// S3 C3: the explorer card and links and the AI section claim exactly the ids their
    /// handlers claimed before (the edits are fields); the AI section's two check boxes carry
    /// their state.
    #[test]
    fn c3_families_map_their_ids() {
        use yw_engine::cmd::{ExplorerLinkAction, ExplorerPress, ExplorerRowAction, LlmPress, Row};
        let controls = ControlSet::default();
        let family = |id: u16| {
            !matches!(
                press_of(id, &controls),
                Press::Legacy(_) | Press::Enter | Press::Back
            )
        };
        for id in 17_200..17_710 {
            let explorer = !matches!(id, 17_200 | 17_201 | 17_209 | 17_218 | 17_219)
                && !(17_448..17_450).contains(&id);
            assert_eq!(family(id), explorer, "{id}");
        }
        for id in 10_000..10_100 {
            let llm = id < 10_022
                && ![
                    screens_llm::ids::ENDPOINT_EDIT,
                    screens_llm::ids::MODEL_EDIT,
                    screens_llm::ids::MAX_TOKENS_EDIT,
                    screens_llm::ids::KEY_EDIT,
                ]
                .contains(&id);
            assert_eq!(family(id), llm, "{id}");
        }
        assert_eq!(
            press_of(screens_explorer::ids::ROW_BASE + 99, &controls),
            Press::Explorer(ExplorerPress::Row(Row(49), ExplorerRowAction::Reset))
        );
        assert_eq!(
            press_of(screens_explorer::ids::ZEC_ACTIVITY_BASE + 158, &controls),
            Press::Explorer(ExplorerPress::ZecActivity(
                Row(79),
                ExplorerLinkAction::Open
            ))
        );
        assert_eq!(
            press_of(screens_llm::ids::ENABLE, &controls),
            Press::Llm(LlmPress::Enable(None))
        );
        controls.type_check(screens_llm::ids::ENABLE, true);
        controls.type_check(screens_llm::ids::NOTICE_CHECK, false);
        assert_eq!(
            press_of(screens_llm::ids::ENABLE, &controls),
            Press::Llm(LlmPress::Enable(Some(true)))
        );
        assert_eq!(
            press_of(screens_llm::ids::NOTICE_CHECK, &controls),
            Press::Llm(LlmPress::NoticeCheck(Some(false)))
        );
    }

    /// S3 C4: the address book claims exactly the ids `on_book_command` claimed before (each
    /// range whole, the three edits are fields); its four check boxes carry their state.
    #[test]
    fn c4_book_maps_its_ids() {
        use screens_book::ids;
        use yw_engine::cmd::{BookPress, BookRowAction, Row};
        let controls = ControlSet::default();
        let family = |id: u16| matches!(press_of(id, &controls), Press::Book(_));
        for id in 14_000..15_700 {
            let book = !matches!(
                id,
                ids::ADDR_EDIT
                    | ids::LABEL_EDIT
                    | ids::PROMPT_LABEL_EDIT
                    | 14_018
                    | 14_019
                    | 14_028
                    | 14_029
                    | 14_070..14_080
                    | 14_144..14_200
            );
            assert_eq!(family(id), book, "{id}");
        }
        for id in 18_690..19_210 {
            assert_eq!(family(id), (18_700..19_200).contains(&id), "{id}");
        }
        assert_eq!(
            press_of(ids::FAV_BASE + 7, &controls),
            Press::Book(BookPress::Chip(Row(7)))
        );
        assert_eq!(
            press_of(ids::ROW_BASE + 1_499, &controls),
            Press::Book(BookPress::Row(Row(499), BookRowAction::Delete))
        );
        assert_eq!(
            press_of(ids::COPY_BASE + 499, &controls),
            Press::Book(BookPress::Copy(Row(499)))
        );
        assert_eq!(
            press_of(ids::SOL_ACTIVITY_BASE + 63, &controls),
            Press::Book(BookPress::SolActivitySave(Row(63)))
        );
        for (id, press) in [
            (
                ids::VERIFIED,
                BookPress::Verified as fn(Option<bool>) -> BookPress,
            ),
            (ids::FAVORITE, BookPress::Favorite),
            (ids::FORM_ACK, BookPress::FormAck),
            (ids::PROMPT_ACK, BookPress::PromptAck),
        ] {
            assert_eq!(press_of(id, &controls), Press::Book(press(None)), "{id}");
            controls.type_check(id, true);
            assert_eq!(
                press_of(id, &controls),
                Press::Book(press(Some(true))),
                "{id}"
            );
            controls.type_check(id, false);
            assert_eq!(
                press_of(id, &controls),
                Press::Book(press(Some(false))),
                "{id}"
            );
            assert_eq!(id_of(press_of(id, &controls)), id);
        }
    }

    /// S3 C5: S22 and T-WAIT-STALLED, S23, the imported-key screens and the `rpc.json` card
    /// claim exactly the ids their handlers claimed before (S22's edit is a field, its 2 s hold
    /// area no press); the S22 check box carries its state, an address-type radio its type.
    #[test]
    fn c5_families_map_their_ids() {
        use yw_core::btc::ScriptType;
        use yw_engine::cmd::{ExtPress, KeysPress, ResetPress, RpcImportPress};
        let controls = ControlSet::default();
        let family = |id: u16| {
            !matches!(
                press_of(id, &controls),
                Press::Legacy(_) | Press::Enter | Press::Back
            )
        };
        for id in 13_400..13_450 {
            let s22 = matches!(id, 13_400 | 13_402 | 13_404 | 13_410 | 13_420..=13_424);
            assert_eq!(family(id), s22, "{id}");
        }
        for id in 13_000..13_200 {
            let keys = matches!(id, 13_000..=13_006 | 13_010..=13_013 | 13_020..=13_027);
            assert_eq!(
                matches!(press_of(id, &controls), Press::Keys(_)),
                keys,
                "{id}"
            );
        }
        for id in 525..545 {
            assert_eq!(
                matches!(press_of(id, &controls), Press::RpcImport(_)),
                (530..=536).contains(&id),
                "{id}"
            );
        }
        assert_eq!(
            press_of(screens_reset::ids::EXT_COPY_PATH, &controls),
            Press::Ext(ExtPress::CopyPath)
        );
        assert_eq!(
            press_of(screens::ids::RPC_JSON_DELETE_CONFIRM, &controls),
            Press::RpcImport(RpcImportPress::DeleteConfirm)
        );
        for script in [
            ScriptType::P2pkh,
            ScriptType::P2shP2wpkh,
            ScriptType::P2wpkh,
            ScriptType::P2tr,
        ] {
            let id = screens_keys::ids::script_id(script);
            assert_eq!(
                press_of(id, &controls),
                Press::Keys(KeysPress::Script(script))
            );
            assert_eq!(id_of(Press::Keys(KeysPress::Script(script))), id);
        }
        let check = screens_reset::ids::RESET_SETTINGS_CHECK;
        assert_eq!(
            press_of(check, &controls),
            Press::Reset(ResetPress::SettingsCheck(None))
        );
        controls.type_check(check, true);
        assert_eq!(
            press_of(check, &controls),
            Press::Reset(ResetPress::SettingsCheck(Some(true)))
        );
        assert_eq!(id_of(press_of(check, &controls)), check);
    }

    /// S3 C6: the recovery phrases claim exactly the ids `on_mn_command` reached (every fixed
    /// id but the two edits, which are fields, and each row range whole).
    #[test]
    fn c6_mn_maps_its_ids() {
        use screens_mnemonics::ids;
        use yw_engine::cmd::{MnPress, Row};
        let controls = ControlSet::default();
        for id in 13_600..13_700 {
            let mn = matches!(id, 13_600..=13_606 | 13_608..=13_614 | 13_620..13_628
                | 13_630..13_638 | 13_640..13_648 | 13_650..13_658 | 13_660..13_668
                | 13_670..13_678 | 13_680..13_688 | 13_690..13_698);
            assert_eq!(matches!(press_of(id, &controls), Press::Mn(_)), mn, "{id}");
        }
        assert!(ids::FIXED.iter().all(|&id| {
            matches!(press_of(id, &controls), Press::Mn(_))
                != [ids::RENAME_EDIT, ids::REMOVE_TYPED_EDIT].contains(&id)
        }));
        assert_eq!(
            press_of(ids::ZEC_PICK_BASE + 7, &controls),
            Press::Mn(MnPress::ZecPick(Row(7)))
        );
        assert_eq!(
            press_of(ids::PICK_BASE, &controls),
            Press::Mn(MnPress::Pick(Row(0)))
        );
    }

    /// S3 C7: `HyperCore` and Zcash claim exactly the ids `on_hc_command` and `on_zec_command`
    /// claimed (every fixed id but the edits, which are fields, and each row range whole); the
    /// two `새로고침` read their received history first and Zcash's two `주소 복사` are gated
    /// (table test (4) checks every id).
    #[test]
    fn c7_hc_and_zec_map_their_ids() {
        use yw_engine::cmd::{HcPress, Row, ZecPress};
        use yw_engine::received::RecvChain;
        let controls = ControlSet::default();
        for id in 13_450..13_500 {
            let hc = matches!(id, 13_450..=13_457 | 13_462..=13_468 | 13_470..=13_490)
                || (13_492..=13_495).contains(&id);
            assert_eq!(matches!(press_of(id, &controls), Press::Hc(_)), hc, "{id}");
        }
        assert!(screens_hypercore::ids::FIXED.iter().all(|&id| {
            use screens_hypercore::ids;
            matches!(press_of(id, &controls), Press::Hc(_))
                != [ids::TO_EDIT, ids::AMOUNT_EDIT, ids::API_EDIT].contains(&id)
        }));
        for id in 8_000..8_200 {
            let zec = matches!(id, 8_000..=8_006 | 8_009..=8_035 | 8_040..=8_047 | 8_050..=8_052
                | 8_060..=8_075 | 8_100..=8_179);
            assert_eq!(
                matches!(press_of(id, &controls), Press::Zec(_)),
                zec,
                "{id}"
            );
        }
        assert_eq!(
            press_of(screens_hypercore::ids::ASSET_BASE + 19, &controls),
            Press::Hc(HcPress::Asset(Row(19)))
        );
        assert_eq!(
            press_of(screens_zec::ids::ACTIVITY_COPY_BASE + 79, &controls),
            Press::Zec(ZecPress::ActivityCopy(Row(79)))
        );
        assert_eq!(
            press_of(screens_zec::ids::HW_BASE, &controls),
            Press::Zec(ZecPress::Hw(Row(0)))
        );
        assert_eq!(
            Press::Hc(HcPress::Refresh).refresh_chain(),
            Some(RecvChain::Hc)
        );
        assert_eq!(
            Press::Zec(ZecPress::Refresh).refresh_chain(),
            Some(RecvChain::Zec)
        );
        assert!(Press::Zec(ZecPress::CopyAddress).is_receive_gated());
        assert!(Press::Zec(ZecPress::CardCopy).is_receive_gated());
        assert!(!Press::Zec(ZecPress::ResultCopy).is_receive_gated());
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
