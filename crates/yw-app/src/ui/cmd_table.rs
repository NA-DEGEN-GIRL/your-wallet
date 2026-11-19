//! The main window's control id ↔ [`Press`] table (spec/04 §2.1, spec/15 §11.4 S3). The window
//! reports a click as a control id (`WM_COMMAND`); `App::on_command` turns it into a
//! `Cmd::Press` with [`press_of`], and [`id_of`] gives the id back where the Windows shell still
//! keys state by id (the copy mark `App::command`, an open drop-down).
//!
//! 2026-11-18 (S3 B2): created. Enter and Esc map to `Press::Enter`/`Press::Back`; every other id
//! was `Press::Legacy(id)` until its handler family was converted (S3 C1–C12; `Legacy` is gone
//! since S3 D3, below).
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
//! `HyperCore` and Zcash. S3 C8: Solana. S3 C9: Bitcoin. S3 C10: the EVM screens. S3 C11: the
//! `YubiKey` card actions, connect flow and wizard (asked in that order, as the handler did).
//! S3 C12: the core screens, settings sections and URL rows (asked first, as the core arms
//! were matched before the family chain).
//!
//! 2026-11-18 (S3 D1): [`capture`] also reads the clipboard for the `WalletConnect` panel's
//! `클립보드에서 연결` and `클립보드 이미지에서 QR 읽기` (`ClipInput`); before, their handlers
//! read it.
//!
//! 2026-11-20 (S4 P5): [`capture`] also reads and decodes the image file of the `WalletConnect`
//! panel's `이미지 파일에서 QR 읽기` (`ImageInput`: the file checks and GDI+ are the shell's);
//! before, its handler opened and decoded the file. The clipboard's `CF_DIB` bytes are moved into
//! a wiped buffer.
//!
//! 2026-11-18 (S3 D3): `Press::Legacy` is gone: [`press_of`] gives `None` for an id no
//! control of the main window sends (an edit's id, S22's painted hold area, the eighth id of a
//! `YubiKey` connect choice row), and `App::on_command` then only records it as the last
//! command id.

use yw_core::secret::Zeroizing;
use yw_engine::cmd::Press;
use yw_engine::form::{ClipInput, CredField, CredUnits, EditField, ImageInput, PressInput};
use yw_win::ui::Window;

use crate::ui::main_window::ControlSet;
use crate::ui::{
    screens, screens_book, screens_btc, screens_evm, screens_explorer, screens_hypercore,
    screens_keys, screens_links, screens_llm, screens_mnemonics, screens_received, screens_reset,
    screens_sites, screens_sol, screens_walletconnect, screens_yubikey, screens_zec,
};
use crate::{app_hidden, app_rpc_import, app_sidecar, app_walletconnect};

/// The command id `IsDialogMessageW` sends for Enter (no control uses it, `ui::command_ids`).
pub const IDOK: u16 = 1;
/// The one it sends for Esc.
pub const IDCANCEL: u16 = 2;

/// The press a control id stands for, with the state of its check box when it is one
/// (`controls.checked(id)` now); `None` for an id that is no press (S3 D3; before,
/// `Press::Legacy(id)`).
#[must_use]
pub fn press_of(id: u16, controls: &ControlSet) -> Option<Press> {
    match id {
        IDOK => Some(Press::Enter),
        IDCANCEL => Some(Press::Back),
        other => screens::ids::press_of(other, controls)
            .map(Press::Core)
            .or_else(|| screens_received::ids::press_of(other, controls).map(Press::Received))
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
            .or_else(|| screens_sol::ids::press_of(other).map(Press::Sol))
            .or_else(|| screens_btc::ids::press_of(other).map(Press::Btc))
            .or_else(|| screens_evm::ids::press_of(other, controls).map(Press::Evm))
            .or_else(|| screens_yubikey::ids::manage_press_of(other).map(Press::YkManage))
            .or_else(|| screens_yubikey::ids::connect_press_of(other).map(Press::YkConnect))
            .or_else(|| screens_yubikey::ids::press_of(other).map(Press::Yk)),
    }
}

/// The control id of a press (the inverse of [`press_of`]; a check box's state is not part of
/// it).
#[must_use]
pub const fn id_of(press: Press) -> u16 {
    match press {
        Press::Enter => IDOK,
        Press::Back => IDCANCEL,
        Press::Core(press) => screens::ids::id_of(press),
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
        Press::Sol(press) => screens_sol::ids::id_of(press),
        Press::Btc(press) => screens_btc::ids::id_of(press),
        Press::Evm(press) => screens_evm::ids::id_of(press),
        Press::Yk(press) => screens_yubikey::ids::id_of(press),
        Press::YkManage(press) => screens_yubikey::ids::manage_id_of(press),
        Press::YkConnect(press) => screens_yubikey::ids::connect_id_of(press),
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
/// For the `WalletConnect` panel's two clipboard presses also what the clipboard holds
/// ([`clip_input`]; S3 D1), read only for them and only with a main window. For its
/// `이미지 파일에서 QR 읽기` also the image file ([`image_input`]; S4 P5), named by the path
/// edit, or by `kept_file` (the path the panel keeps, `wc.file_text`) when that edit does not
/// exist — the path the handler used before P5 (the form state, else the kept text).
#[must_use]
pub fn capture(
    id: u16,
    controls: &ControlSet,
    main: Option<&Window>,
    kept_file: &str,
) -> PressInput {
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
    let input = PressInput::new(creds);
    match id {
        screens_walletconnect::ids::CLIPBOARD_CONNECT => {
            input.with_clip(clip_input(main, ClipRead::LinkOrImage))
        }
        screens_walletconnect::ids::CLIPBOARD_QR => {
            input.with_clip(clip_input(main, ClipRead::Image))
        }
        screens_walletconnect::ids::FILE_QR => {
            let field = controls.text(edit_id_of(EditField::WcFile), EditField::WcFile.cap());
            input.with_image(image_input(field.as_deref().unwrap_or(kept_file)))
        }
        _ => input,
    }
}

/// Reads the image file for `이미지 파일에서 QR 읽기` (2026-11-20, S4 P5; the checks and the
/// decode the former `App::wc_file_qr` made, in the same order, spec/13 §6): `field` is the path
/// field (spaces and the quotes of Explorer's `경로로 복사` trimmed); only a regular file of at
/// most `MAX_IMAGE_FILE` bytes with a PNG, JPEG, BMP or GIF signature is handed to GDI+
/// (`yw_win::image::decode_file`, no other codec on untrusted files). The pixels move into a
/// wiped buffer without a copy.
fn image_input(field: &str) -> ImageInput {
    let path = field.trim().trim_matches('"');
    if path.is_empty() {
        return ImageInput::NoPath;
    }
    let path = std::path::Path::new(path);
    if !image_file_acceptable(path) {
        return ImageInput::Refused;
    }
    match yw_win::image::decode_file(path) {
        Ok(image) => ImageInput::Pixels {
            width: image.width,
            height: image.height,
            pixels: Zeroizing::new(image.pixels),
        },
        Err(_) => ImageInput::Unreadable,
    }
}

/// A regular file of at most `MAX_IMAGE_FILE` bytes with an accepted signature
/// (`app_walletconnect::image_magic_ok`). 2026-11-20 (S4 P5): moved unchanged from
/// `app_walletconnect`.
fn image_file_acceptable(path: &std::path::Path) -> bool {
    use std::io::Read as _;
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let size_ok = file
        .metadata()
        .is_ok_and(|meta| meta.is_file() && meta.len() <= app_walletconnect::MAX_IMAGE_FILE);
    let mut head = [0_u8; 8];
    size_ok
        && file.take(8).read_exact(&mut head).is_ok()
        && app_walletconnect::image_magic_ok(&head)
}

/// What a clipboard press reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClipRead {
    /// `클립보드에서 연결`: a copied pairing link (text), else a copied image.
    LinkOrImage,
    /// `클립보드 이미지에서 QR 읽기`: a copied image.
    Image,
}

/// Reads the clipboard for a `WalletConnect` press (2026-11-18, S3 D1; the sequence of the
/// former `App::wc_clipboard_connect`/`wc_clipboard_qr` reads, spec/13 §6): no main window →
/// nothing read; for `LinkOrImage` first `CF_UNICODETEXT` (at most 2 048 units), a pairing link
/// when [`clip_link`] finds one; otherwise (no text, other text, or the text could not be read)
/// the `CF_DIB` bitmap (at most `MAX_CLIPBOARD_IMAGE` bytes).
fn clip_input(main: Option<&Window>, read: ClipRead) -> ClipInput {
    let Some(main) = main else {
        return ClipInput::NoWindow;
    };
    if read == ClipRead::LinkOrImage
        && let Some(link) = yw_win::clipboard::read_text(main, 2_048)
            .ok()
            .and_then(|(units, _)| clip_link(units.as_slice()))
    {
        return ClipInput::Link(link);
    }
    match yw_win::clipboard::read_dib(main, app_walletconnect::MAX_CLIPBOARD_IMAGE) {
        // 2026-11-20 (S4 P5): moved into a wiped buffer (no copy); before, a plain `Vec`.
        Ok(Some(dib)) => ClipInput::WinDib(Zeroizing::new(dib)),
        Ok(None) => ClipInput::NoImage,
        Err(_) => ClipInput::OpenFailed,
    }
}

/// The clipboard text `units` as a pairing link: `Some` only when, after leading whitespace,
/// it starts like one (`app_walletconnect::units_look_like_pairing_link`, checked on the units);
/// any other text (it may be a copied secret) is never copied out of the wiped buffer.
fn clip_link(units: &[u16]) -> Option<Zeroizing<String>> {
    let start = units
        .iter()
        .position(|unit| !char::from_u32(u32::from(*unit)).is_some_and(char::is_whitespace))?;
    app_walletconnect::units_look_like_pairing_link(units.get(start..)?)
        .then(|| Zeroizing::new(String::from_utf16_lossy(units)))
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

    /// Table test (1): the table is injective and round-trips every id that is a press (S3 D3:
    /// the others are exactly those of `only_unclaimed_ids_are_no_press`).
    #[test]
    fn every_id_round_trips() {
        let ids = every_id();
        assert!(ids.len() > 1_000, "{}", ids.len());
        let controls = ControlSet::default();
        let mut presses = 0;
        for id in ids {
            assert!(id != IDOK && id != IDCANCEL, "{id} is Enter or Esc");
            let Some(press) = press_of(id, &controls) else {
                continue;
            };
            presses += 1;
            assert_eq!(id_of(press), id, "{id}");
        }
        assert!(presses > 1_000, "{presses}");
        assert_eq!(press_of(IDOK, &controls).unwrap(), Press::Enter);
        assert_eq!(press_of(IDCANCEL, &controls).unwrap(), Press::Back);
        assert_eq!(id_of(Press::Enter), IDOK);
        assert_eq!(id_of(Press::Back), IDCANCEL);
    }

    /// Table test (6): S22's 2 s hold area is painted, not a control; it never becomes a family
    /// press that a click could post.
    #[test]
    fn reset_hold_stays_unpressable() {
        let hold = screens_reset::ids::RESET_HOLD;
        assert_eq!(press_of(hold, &ControlSet::default()), None);
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
            let Some(press) = press_of(id, &controls) else {
                continue;
            };
            if matches!(press, Press::Enter | Press::Back) {
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
                None | Some(Press::Enter | Press::Back)
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
            press_of(app_hidden::ids::BTC_ROW_BASE + 64, &controls).unwrap(),
            Press::Hidden(HiddenPress::BtcUnhide(Row(64)))
        );
        assert_eq!(
            press_of(screens_links::ids::ZEC_TO_BASE + 79, &controls).unwrap(),
            Press::Links(LinksPress::ZecTo(Row(79)))
        );
        assert_eq!(
            press_of(screens_received::ids::ROW_BASE + 499, &controls).unwrap(),
            Press::Received(ReceivedPress::OpenExplorer(RecvChain::Zec, Row(49)))
        );
        // A check box's state travels with the press.
        let toggle = screens_received::ids::toggle(RecvChain::Btc);
        assert_eq!(
            press_of(toggle, &controls).unwrap(),
            Press::Received(ReceivedPress::Toggle {
                chain: RecvChain::Btc,
                checked: None
            })
        );
        controls.type_check(toggle, true);
        controls.type_check(app_sidecar::ids::RESET_ACK, false);
        assert_eq!(
            press_of(toggle, &controls).unwrap(),
            Press::Received(ReceivedPress::Toggle {
                chain: RecvChain::Btc,
                checked: Some(true)
            })
        );
        assert_eq!(
            press_of(app_sidecar::ids::RESET_ACK, &controls).unwrap(),
            Press::Sidecar(SidecarPress::ResetAck(Some(false)))
        );
        assert_eq!(id_of(press_of(toggle, &controls).unwrap()), toggle);
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
                None | Some(Press::Enter | Press::Back)
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
            press_of(screens_sites::ids::SITE_ROW_BASE + 255, &controls).unwrap(),
            Press::Sites(SitesPress::Disconnect(Row(255)))
        );
        assert_eq!(
            press_of(screens_walletconnect::ids::ROW_BASE + 63, &controls).unwrap(),
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
                None | Some(Press::Enter | Press::Back)
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
            press_of(screens_explorer::ids::ROW_BASE + 99, &controls).unwrap(),
            Press::Explorer(ExplorerPress::Row(Row(49), ExplorerRowAction::Reset))
        );
        assert_eq!(
            press_of(screens_explorer::ids::ZEC_ACTIVITY_BASE + 158, &controls).unwrap(),
            Press::Explorer(ExplorerPress::ZecActivity(
                Row(79),
                ExplorerLinkAction::Open
            ))
        );
        assert_eq!(
            press_of(screens_llm::ids::ENABLE, &controls).unwrap(),
            Press::Llm(LlmPress::Enable(None))
        );
        controls.type_check(screens_llm::ids::ENABLE, true);
        controls.type_check(screens_llm::ids::NOTICE_CHECK, false);
        assert_eq!(
            press_of(screens_llm::ids::ENABLE, &controls).unwrap(),
            Press::Llm(LlmPress::Enable(Some(true)))
        );
        assert_eq!(
            press_of(screens_llm::ids::NOTICE_CHECK, &controls).unwrap(),
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
        let family = |id: u16| matches!(press_of(id, &controls), Some(Press::Book(_)));
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
            press_of(ids::FAV_BASE + 7, &controls).unwrap(),
            Press::Book(BookPress::Chip(Row(7)))
        );
        assert_eq!(
            press_of(ids::ROW_BASE + 1_499, &controls).unwrap(),
            Press::Book(BookPress::Row(Row(499), BookRowAction::Delete))
        );
        assert_eq!(
            press_of(ids::COPY_BASE + 499, &controls).unwrap(),
            Press::Book(BookPress::Copy(Row(499)))
        );
        assert_eq!(
            press_of(ids::SOL_ACTIVITY_BASE + 63, &controls).unwrap(),
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
            assert_eq!(
                press_of(id, &controls).unwrap(),
                Press::Book(press(None)),
                "{id}"
            );
            controls.type_check(id, true);
            assert_eq!(
                press_of(id, &controls).unwrap(),
                Press::Book(press(Some(true))),
                "{id}"
            );
            controls.type_check(id, false);
            assert_eq!(
                press_of(id, &controls).unwrap(),
                Press::Book(press(Some(false))),
                "{id}"
            );
            assert_eq!(id_of(press_of(id, &controls).unwrap()), id);
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
                None | Some(Press::Enter | Press::Back)
            )
        };
        for id in 13_400..13_450 {
            let s22 = matches!(id, 13_400 | 13_402 | 13_404 | 13_410 | 13_420..=13_424);
            assert_eq!(family(id), s22, "{id}");
        }
        for id in 13_000..13_200 {
            let keys = matches!(id, 13_000..=13_006 | 13_010..=13_013 | 13_020..=13_027);
            assert_eq!(
                matches!(press_of(id, &controls), Some(Press::Keys(_))),
                keys,
                "{id}"
            );
        }
        for id in 525..545 {
            assert_eq!(
                matches!(press_of(id, &controls), Some(Press::RpcImport(_))),
                (530..=536).contains(&id),
                "{id}"
            );
        }
        assert_eq!(
            press_of(screens_reset::ids::EXT_COPY_PATH, &controls).unwrap(),
            Press::Ext(ExtPress::CopyPath)
        );
        assert_eq!(
            press_of(screens::ids::RPC_JSON_DELETE_CONFIRM, &controls).unwrap(),
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
                press_of(id, &controls).unwrap(),
                Press::Keys(KeysPress::Script(script))
            );
            assert_eq!(id_of(Press::Keys(KeysPress::Script(script))), id);
        }
        let check = screens_reset::ids::RESET_SETTINGS_CHECK;
        assert_eq!(
            press_of(check, &controls).unwrap(),
            Press::Reset(ResetPress::SettingsCheck(None))
        );
        controls.type_check(check, true);
        assert_eq!(
            press_of(check, &controls).unwrap(),
            Press::Reset(ResetPress::SettingsCheck(Some(true)))
        );
        assert_eq!(id_of(press_of(check, &controls).unwrap()), check);
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
            assert_eq!(
                matches!(press_of(id, &controls), Some(Press::Mn(_))),
                mn,
                "{id}"
            );
        }
        assert!(ids::FIXED.iter().all(|&id| {
            matches!(press_of(id, &controls), Some(Press::Mn(_)))
                != [ids::RENAME_EDIT, ids::REMOVE_TYPED_EDIT].contains(&id)
        }));
        assert_eq!(
            press_of(ids::ZEC_PICK_BASE + 7, &controls).unwrap(),
            Press::Mn(MnPress::ZecPick(Row(7)))
        );
        assert_eq!(
            press_of(ids::PICK_BASE, &controls).unwrap(),
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
            assert_eq!(
                matches!(press_of(id, &controls), Some(Press::Hc(_))),
                hc,
                "{id}"
            );
        }
        assert!(screens_hypercore::ids::FIXED.iter().all(|&id| {
            use screens_hypercore::ids;
            matches!(press_of(id, &controls), Some(Press::Hc(_)))
                != [ids::TO_EDIT, ids::AMOUNT_EDIT, ids::API_EDIT].contains(&id)
        }));
        for id in 8_000..8_200 {
            let zec = matches!(id, 8_000..=8_006 | 8_009..=8_035 | 8_040..=8_047 | 8_050..=8_052
                | 8_060..=8_075 | 8_100..=8_179);
            assert_eq!(
                matches!(press_of(id, &controls), Some(Press::Zec(_))),
                zec,
                "{id}"
            );
        }
        assert_eq!(
            press_of(screens_hypercore::ids::ASSET_BASE + 19, &controls).unwrap(),
            Press::Hc(HcPress::Asset(Row(19)))
        );
        assert_eq!(
            press_of(screens_zec::ids::ACTIVITY_COPY_BASE + 79, &controls).unwrap(),
            Press::Zec(ZecPress::ActivityCopy(Row(79)))
        );
        assert_eq!(
            press_of(screens_zec::ids::HW_BASE, &controls).unwrap(),
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

    /// S3 C8: Solana claims exactly the ids `on_sol_command` claimed (every fixed id but the
    /// five edits, which are fields, and each row range whole); a scan row's two buttons keep
    /// their row and action; `새로고침` reads its received history first and `받기`/`주소 복사`
    /// are gated (table test (4) checks every id).
    #[test]
    fn c8_sol_maps_its_ids() {
        use screens_sol::ids;
        use yw_engine::cmd::{Row, SolPress, SolScanAction};
        use yw_engine::received::RecvChain;
        let controls = ControlSet::default();
        for id in 7_000..7_910 {
            let sol = matches!(id, 7_000..=7_010 | 7_012..=7_019 | 7_022..=7_073 | 7_075 | 7_076
                | 7_080..=7_083 | 7_100 | 7_103..=7_106 | 7_110..=7_112 | 7_120..=7_375
                | 7_400..=7_463);
            assert_eq!(
                matches!(press_of(id, &controls), Some(Press::Sol(_))),
                sol,
                "{id}"
            );
        }
        for id in 11_990..13_000 {
            assert_eq!(
                matches!(press_of(id, &controls), Some(Press::Sol(_))),
                id >= 12_000,
                "{id}"
            );
        }
        assert!(ids::FIXED.iter().all(|&id| {
            matches!(press_of(id, &controls), Some(Press::Sol(_)))
                != [
                    ids::RENAME_EDIT,
                    ids::SEND_TO_EDIT,
                    ids::SEND_AMOUNT_EDIT,
                    ids::FEE_CAP_EDIT,
                    ids::CU_PRICE_EDIT,
                ]
                .contains(&id)
        }));
        for row in 0..128_usize {
            for (action, scan) in [
                (ids::ScanAction::Add(row), SolScanAction::Add),
                (ids::ScanAction::Move(row), SolScanAction::Move),
            ] {
                let id = ids::scan_row_id(action).unwrap();
                let press = SolPress::ScanRow(Row(u16::try_from(row).unwrap()), scan);
                assert_eq!(press_of(id, &controls).unwrap(), Press::Sol(press), "{id}");
                assert_eq!(id_of(Press::Sol(press)), id);
            }
        }
        assert_eq!(
            press_of(ids::ACCOUNT_BASE + 999, &controls).unwrap(),
            Press::Sol(SolPress::Account(Row(999)))
        );
        assert_eq!(
            press_of(ids::SEND_PICK_BASE + 39, &controls).unwrap(),
            Press::Sol(SolPress::SendPickRow(Row(39)))
        );
        assert_eq!(
            Press::Sol(SolPress::Refresh).refresh_chain(),
            Some(RecvChain::Sol)
        );
        assert!(Press::Sol(SolPress::ReceiveOpen).is_receive_gated());
        assert!(Press::Sol(SolPress::CopyAddress).is_receive_gated());
        assert!(!Press::Sol(SolPress::TokenCopy(Row(0))).is_receive_gated());
    }

    /// S3 C9: Bitcoin claims exactly the ids `on_btc_command` claimed (every fixed id but the
    /// nine edits, which are fields, and each row range whole); an address-type radio carries
    /// its `ScriptType`, an Esplora button its network, an activity button its row and action;
    /// `새로고침` reads its received history first, `받기` and the card's `주소 복사` are gated
    /// (table test (4) checks every id).
    #[test]
    fn c9_btc_maps_its_ids() {
        use screens_btc::ids;
        use yw_core::btc::{BtcNetwork, ScriptType};
        use yw_engine::cmd::{BtcActivityAction, BtcPress, Row};
        use yw_engine::received::RecvChain;
        let controls = ControlSet::default();
        for id in 9_000..10_000 {
            let btc = matches!(id, 9_000..=9_019 | 9_022..=9_028 | 9_031..=9_036 | 9_038..=9_042
                | 9_050..=9_053 | 9_056 | 9_057 | 9_060..=9_095 | 9_100..=9_105
                | 9_111..=9_113 | 9_121..=9_123 | 9_130..=9_194 | 9_200..=9_899);
            assert_eq!(
                matches!(press_of(id, &controls), Some(Press::Btc(_))),
                btc,
                "{id}"
            );
        }
        let edits = [
            ids::SEND_TO_EDIT,
            ids::SEND_AMOUNT_EDIT,
            ids::FEE_MANUAL_EDIT,
            ids::TYPED_FEE_EDIT,
            ids::BUMP_MANUAL_EDIT,
            ids::BUMP_TYPED_EDIT,
            ids::RENAME_EDIT,
            ids::ESPLORA_MAINNET_EDIT,
            ids::ESPLORA_TESTNET4_EDIT,
        ];
        assert!(ids::FIXED.iter().all(|&id| {
            matches!(press_of(id, &controls), Some(Press::Btc(_))) != edits.contains(&id)
        }));
        for (position, script) in ScriptType::CHOICES.into_iter().enumerate() {
            let id = ids::ACCOUNT_ADD_TYPE + u16::try_from(position).unwrap();
            assert_eq!(
                press_of(id, &controls).unwrap(),
                Press::Btc(BtcPress::AccountAddType(script))
            );
        }
        for net in BtcNetwork::ALL {
            let (_, save, default, test) = screens_btc::esplora_ids(net);
            assert_eq!(
                press_of(save, &controls).unwrap(),
                Press::Btc(BtcPress::EsploraSave(net))
            );
            assert_eq!(
                press_of(default, &controls).unwrap(),
                Press::Btc(BtcPress::EsploraDefault(net))
            );
            assert_eq!(
                press_of(test, &controls).unwrap(),
                Press::Btc(BtcPress::EsploraTest(net))
            );
        }
        let actions = [
            (ids::ACT_COPY, BtcActivityAction::CopyHash),
            (ids::ACT_BUMP, BtcActivityAction::Bump),
            (ids::ACT_REBROADCAST, BtcActivityAction::Rebroadcast),
            (ids::ACT_ABANDON, BtcActivityAction::Abandon),
            (ids::ACT_ESPLORA, BtcActivityAction::Esplora),
            (ids::ACT_CONTINUE, BtcActivityAction::Continue),
            (ids::ACT_CANCEL, BtcActivityAction::Cancel),
            (ids::ACT_SAVE, BtcActivityAction::SaveAddress),
        ];
        for row in 0..ids::ACTIVITY_SPAN / ids::ACTIVITY_STRIDE {
            for (offset, action) in actions {
                let id = ids::ACTIVITY_BASE + row * ids::ACTIVITY_STRIDE + offset;
                assert_eq!(
                    press_of(id, &controls).unwrap(),
                    Press::Btc(BtcPress::Activity(Row(row), action)),
                    "{id}"
                );
            }
        }
        for (id, press) in [
            (ids::FEE_MANUAL, BtcPress::FeeManual),
            (ids::BUMP_FEE_FAST, BtcPress::BumpFeeFast),
            (ids::ACCOUNT_BASE + 64, BtcPress::Account(Row(64))),
            (ids::UTXO_BASE + 299, BtcPress::Utxo(Row(299))),
            (ids::EVM_ACCOUNT_BASE + 31, BtcPress::EvmAccount(Row(31))),
        ] {
            assert_eq!(press_of(id, &controls).unwrap(), Press::Btc(press), "{id}");
        }
        assert_eq!(
            Press::Btc(BtcPress::Refresh).refresh_chain(),
            Some(RecvChain::Btc)
        );
        assert!(Press::Btc(BtcPress::ReceiveOpen).is_receive_gated());
        assert!(Press::Btc(BtcPress::CardCopy).is_receive_gated());
        assert!(!Press::Btc(BtcPress::CopyAddress).is_receive_gated());
    }

    /// S3 C10: the EVM screens claim exactly the ids `on_evm_command` claimed (every fixed id
    /// but the thirteen edits, which are fields, and each row range whole); the three check
    /// boxes carry their state, a chain or activity row button its row and action; `새로고침`
    /// reads its received history first, `받기` and `주소 복사` are gated (table test (4) checks
    /// every id).
    #[test]
    fn c10_evm_maps_its_ids() {
        use screens_evm::ids;
        use yw_engine::cmd::{ChainRowAction, EvmActivityAction, EvmPress, Row};
        use yw_engine::received::RecvChain;
        let controls = ControlSet::default();
        let evm = |id: u16| matches!(press_of(id, &controls), Some(Press::Evm(_)));
        let edits = [
            ids::SEND_TO_EDIT,
            ids::SEND_AMOUNT_EDIT,
            ids::TOKEN_ADDR_EDIT,
            ids::TOKEN_LABEL_EDIT,
            ids::CHAIN_ID_EDIT,
            ids::CHAIN_NAME_EDIT,
            ids::CHAIN_SYMBOL_EDIT,
            ids::CHAIN_DECIMALS_EDIT,
            ids::CHAIN_RPC_EDIT,
            ids::CHAIN_EXPLORER_EDIT,
            ids::CAPS_FEE_EDIT,
            ids::CAPS_TIP_EDIT,
            ids::CAPS_TOTAL_EDIT,
        ];
        assert!(ids::FIXED.iter().all(|&id| evm(id) != edits.contains(&id)));
        for id in 900..3_600 {
            let fixed = ids::FIXED.contains(&id) && !edits.contains(&id);
            let ranged = matches!(id, 960..1_000 | 1_010..1_130 | 2_210..2_350 | 2_400..2_440
                | 2_500..2_900 | 3_000..3_200 | 3_200..3_440 | 3_440..3_560);
            assert_eq!(evm(id), fixed || ranged, "{id}");
        }
        assert!(evm(ids::REPIN_CHECK) && !evm(ids::REPIN_CHECK + 1));
        for row in 0..ids::CHAIN_ROW_SPAN {
            let action = [
                ChainRowAction::Edit,
                ChainRowAction::Delete,
                ChainRowAction::Repin,
            ][usize::from(row % 3)];
            let id = ids::CHAIN_ROW_BASE + row;
            assert_eq!(
                press_of(id, &controls).unwrap(),
                Press::Evm(EvmPress::ChainRow(Row(row / 3), action)),
                "{id}"
            );
        }
        let actions = [
            EvmActivityAction::CopyHash,
            EvmActivityAction::SpeedUp,
            EvmActivityAction::Cancel,
            EvmActivityAction::Resend,
            EvmActivityAction::Discard,
            EvmActivityAction::CopyExplorerLink,
            EvmActivityAction::SaveAddress,
            EvmActivityAction::OpenExplorer,
        ];
        for row in 0..ids::ACTIVITY_SPAN / ids::ACTIVITY_STRIDE {
            for (offset, action) in (0..).zip(actions) {
                let id = ids::ACTIVITY_BASE + row * ids::ACTIVITY_STRIDE + offset;
                assert_eq!(
                    press_of(id, &controls).unwrap(),
                    Press::Evm(EvmPress::Activity(Row(row), action)),
                    "{id}"
                );
            }
        }
        for (id, press) in [
            (ids::SEND_ASSET_BASE + 199, EvmPress::SendAsset(Row(199))),
            (ids::TOKEN_SEND_BASE + 119, EvmPress::TokenSend(Row(119))),
            (ids::TOKEN_COPY_BASE + 119, EvmPress::TokenCopy(Row(119))),
            (ids::SEND_PICK_BASE + 39, EvmPress::PickRecipient(Row(39))),
            (ids::CAPS_CHAIN_BASE + 39, EvmPress::CapsChain(Row(39))),
        ] {
            assert_eq!(press_of(id, &controls).unwrap(), Press::Evm(press), "{id}");
        }
        assert_eq!(
            Press::Evm(EvmPress::Refresh).refresh_chain(),
            Some(RecvChain::Evm)
        );
        assert!(Press::Evm(EvmPress::ReceiveOpen).is_receive_gated());
        assert!(Press::Evm(EvmPress::CopyAddress).is_receive_gated());
        assert!(!Press::Evm(EvmPress::TokenCopy(Row(0))).is_receive_gated());
    }

    /// S3 C10: an EVM token row's two buttons are the ids `token_row_id` draws; the three check
    /// boxes carry their state.
    #[test]
    fn c10_evm_token_rows_and_checks() {
        use screens_evm::ids;
        use yw_engine::cmd::{EvmPress, Row};
        let controls = ControlSet::default();
        for row in 0..ids::TOKEN_ROW_SPAN / ids::TOKEN_ROW_STRIDE {
            let usize_row = usize::from(row);
            assert_eq!(
                Some(id_of(Press::Evm(EvmPress::TokenToggleHidden(Row(row))))),
                ids::token_row_id(ids::TokenAction::ToggleHidden(usize_row))
            );
            assert_eq!(
                Some(id_of(Press::Evm(EvmPress::TokenDelete(Row(row))))),
                ids::token_row_id(ids::TokenAction::Delete(usize_row))
            );
        }
        for (id, press) in [
            (
                ids::SEND_ACK,
                EvmPress::SendAck as fn(Option<bool>) -> EvmPress,
            ),
            (ids::TOKEN_HIDE_ZERO, EvmPress::TokenHideZero),
            (ids::REPIN_CHECK, EvmPress::RepinCheck),
        ] {
            assert_eq!(
                press_of(id, &controls).unwrap(),
                Press::Evm(press(None)),
                "{id}"
            );
            controls.type_check(id, true);
            assert_eq!(
                press_of(id, &controls).unwrap(),
                Press::Evm(press(Some(true)))
            );
            controls.type_check(id, false);
            assert_eq!(
                press_of(id, &controls).unwrap(),
                Press::Evm(press(Some(false)))
            );
            assert_eq!(id_of(press_of(id, &controls).unwrap()), id);
        }
    }

    /// S3 C11: the `YubiKey` screens claim exactly the ids `on_yk_command` claimed (directly or
    /// through the card-action and connect handlers it asked first): every fixed id but the
    /// eleven edits, which are fields, each row range whole and every choice radio; the eighth
    /// id of a connect choice row, which is no radio, stays unclaimed as before (S3 D3: no press).
    #[test]
    fn c11_yubikey_maps_its_ids() {
        use screens_yubikey::ids;
        let controls = ControlSet::default();
        let yk = |id: u16| {
            matches!(
                press_of(id, &controls),
                Some(Press::Yk(_) | Press::YkManage(_) | Press::YkConnect(_))
            )
        };
        let edits = [
            ids::SIG_INDEX_EDIT,
            ids::AUT_INDEX_EDIT,
            ids::SOL_COUNT_EDIT,
            ids::SOL_START_EDIT,
            ids::RESLOT_SIG_INDEX_EDIT,
            ids::RESLOT_AUT_INDEX_EDIT,
            ids::CLEAR_CONFIRM_EDIT,
            ids::CARD_NAME_EDIT,
            ids::RESLOT_LOSS_EDIT,
            ids::CLEAR_LOSS_EDIT,
            ids::OVERWRITE_EDIT,
        ];
        assert!(ids::FIXED.iter().all(|&id| yk(id) != edits.contains(&id)));
        for id in 13_200..13_960 {
            let ranged = matches!(id, 13_260..13_268 | 13_270..13_278 | 13_300..13_308 | 13_310..13_318 | 13_320..13_328
                | 13_370..13_378 | 13_510..13_518 | 13_530..13_538)
                || (13_720..13_928).contains(&id) && (id - 13_720) % 8 != 7;
            let fixed = ids::FIXED.contains(&id) && !edits.contains(&id);
            assert_eq!(yk(id), fixed || ranged, "{id}");
        }
        // Each id goes to the family whose handler took it.
        for id in ids::FIXED.iter().copied().chain(13_200..13_960) {
            let manage = ids::reslot_row(id).is_some()
                || ids::clear_row(id).is_some()
                || ids::reslot_backup_row(id).is_some()
                || ids::reslot_action(id).is_some()
                || ids::preset(id).is_some()
                || (13_358..=13_368).contains(&id)
                || matches!(
                    id,
                    13_380..=13_385 | 13_387 | 13_390 | 13_392 | 13_394 | 13_520 | 13_523
                );
            let connect = ids::connect_choice(id).is_some() || (13_500..=13_506).contains(&id);
            assert_eq!(
                matches!(press_of(id, &controls), Some(Press::YkManage(_))),
                manage,
                "{id}"
            );
            assert_eq!(
                matches!(press_of(id, &controls), Some(Press::YkConnect(_))),
                connect,
                "{id}"
            );
        }
    }

    /// S3 C11: the `YubiKey` radios carry the choice the id's decoder gives, and map back to it
    /// (`pgp_of`, `reslot_of`, `preset_of`, `choice_of`).
    #[test]
    fn c11_yubikey_radios_carry_their_choice() {
        use screens_yubikey::ids;
        let controls = ControlSet::default();
        for id in 13_200..13_960 {
            match press_of(id, &controls) {
                Some(Press::Yk(press)) => {
                    assert_eq!(ids::pgp_of(press), ids::pgp_action(id), "{id}");
                }
                Some(Press::YkManage(press)) => {
                    assert_eq!(ids::reslot_of(press), ids::reslot_action(id), "{id}");
                    assert_eq!(ids::preset_of(press), ids::preset(id), "{id}");
                }
                Some(Press::YkConnect(press)) => {
                    assert_eq!(ids::choice_of(press), ids::connect_choice(id), "{id}");
                }
                _ => {}
            }
        }
    }

    /// S3 C12: the core screens claim exactly the ids the core arms of the legacy dispatcher
    /// and `on_indexed_command` claimed: every fixed id of `screens::ids` but the seven edits
    /// (fields, credentials) and the `rpc.json` card (C5), and the four row ranges whole; the
    /// five check boxes carry their state, the radios their language, template or log level.
    #[test]
    fn c12_core_maps_its_ids() {
        use crate::ui::screens::ids;
        use yw_core::lang::Lang;
        use yw_engine::cmd::{CorePress, Row, RpcRowAction};
        use yw_engine::logging::LogLevel;
        use yw_engine::settings::RpcTemplate;
        let controls = ControlSet::default();
        let core = |id: u16| matches!(press_of(id, &controls), Some(Press::Core(_)));
        for &id in ids::FIXED {
            let other = field_of(id).is_some()
                || cred_of(id).is_some()
                || (ids::RPC_IMPORT..=ids::RPC_JSON_DELETE_CANCEL).contains(&id);
            assert_eq!(core(id), !other, "{id}");
        }
        for (base, span) in [
            (ids::NETWORK_BASE, ids::NETWORK_SPAN),
            (ids::ACCOUNT_BASE, ids::ACCOUNT_SPAN),
            (ids::RPC_ROW_OPEN_BASE, ids::RPC_ROW_OPEN_SPAN),
            (ids::ROW_BASE, ids::ROW_SPAN),
        ] {
            assert!(
                !core(base - 1) || ids::FIXED.contains(&(base - 1)),
                "{base}"
            );
            assert!((base..base + span).all(core), "{base}");
            assert!(
                !core(base + span) || ids::FIXED.contains(&(base + span)),
                "{base}"
            );
        }
        for offset in 0..ids::ROW_SPAN {
            let action = [
                RpcRowAction::Replace,
                RpcRowAction::Test,
                RpcRowAction::Delete,
            ][usize::from(offset % 3)];
            assert_eq!(
                press_of(ids::ROW_BASE + offset, &controls).unwrap(),
                Press::Core(CorePress::RpcRow(Row(offset / 3), action))
            );
        }
        for (id, press) in [
            (ids::LANG_KO, CorePress::Lang(Lang::Ko)),
            (ids::LANG_EN, CorePress::Lang(Lang::En)),
            (
                ids::TPL_QUICKNODE,
                CorePress::Template(RpcTemplate::QuickNode),
            ),
            (ids::TPL_ALCHEMY, CorePress::Template(RpcTemplate::Alchemy)),
            (ids::TPL_MANUAL, CorePress::Template(RpcTemplate::Manual)),
            (ids::LOG_ERROR, CorePress::LogLevel(LogLevel::Error)),
            (ids::LOG_WARN, CorePress::LogLevel(LogLevel::Warn)),
            (ids::LOG_INFO, CorePress::LogLevel(LogLevel::Info)),
            (ids::LOG_DEBUG, CorePress::LogLevel(LogLevel::Debug)),
            (ids::ACCOUNT_BASE + 999, CorePress::Account(Row(999))),
            (ids::NETWORK_BASE + 39, CorePress::Network(Row(39))),
            (ids::RPC_ROW_OPEN_BASE + 63, CorePress::RpcRowOpen(Row(63))),
        ] {
            assert_eq!(press_of(id, &controls).unwrap(), Press::Core(press), "{id}");
        }
        for (id, press) in [
            (
                ids::MISMATCH_CHECK,
                CorePress::MismatchCheck as fn(Option<bool>) -> CorePress,
            ),
            (ids::COPY_TOGGLE, CorePress::CopyToggle),
            (ids::LOCALHOST_TOGGLE, CorePress::LocalhostToggle),
            (ids::AUTOLAUNCH_TOGGLE, CorePress::AutolaunchToggle),
            (ids::OVERWRITE_CHECK, CorePress::OverwriteCheck),
        ] {
            assert_eq!(
                press_of(id, &controls).unwrap(),
                Press::Core(press(None)),
                "{id}"
            );
            controls.type_check(id, true);
            assert_eq!(
                press_of(id, &controls).unwrap(),
                Press::Core(press(Some(true)))
            );
            controls.type_check(id, false);
            assert_eq!(
                press_of(id, &controls).unwrap(),
                Press::Core(press(Some(false)))
            );
            assert_eq!(id_of(press_of(id, &controls).unwrap()), id);
        }
    }

    /// S3 C10–C12 review: the reverse direction of table test (1) for the C10–C12 families.
    /// Every payload value their presses can hold (each script type, touch policy, Zcash
    /// network, connect choice, row action, radio value and the check boxes' unread state) and
    /// every row variant at its last row inside the span and at the first row past it maps to
    /// an id that decodes back to the same press, except the values the screens never draw,
    /// listed here: a Taproot script radio (wizard, re-slot, connect), the `Never` touch radio
    /// and a row past its span. Their ids belong to another control (a slot's index edit, a
    /// connect row's EVM radio, a neighbouring range), so `id_of` is not one to one there.
    /// Windows only sends drawn ids, so nothing changes today; once a press arrives as data
    /// (S3 D3, S5, Android) such a value must be refused before `on_press` anchors
    /// `App::command` on it (plan D-c; S4/S5: enums that cannot hold them, no id past a span).
    #[test]
    #[expect(clippy::too_many_lines, reason = "one table of every payload value")]
    fn c10_c12_payloads_round_trip_or_are_undrawn() {
        use crate::ui::screens::ids as core;
        use screens_evm::ids as evm;
        use screens_yubikey::ids as yk;
        use yw_core::btc::ScriptType;
        use yw_core::lang::Lang;
        use yw_core::yubikey::plan::{PgpKey, TouchPolicy};
        use yw_core::zec::ZecNetwork;
        use yw_engine::cmd::{
            ChainRowAction, CorePress, EvmActivityAction, EvmPress, Row, RpcRowAction,
            YkConnectPress, YkManagePress, YkPress,
        };
        use yw_engine::logging::LogLevel;
        use yw_engine::settings::RpcTemplate;
        // A row variant's press for a row.
        type RowPress = fn(Row) -> Press;
        // The exhaustive matches fail to compile on a new variant until it is placed here.
        const fn script_drawn(script: ScriptType) -> bool {
            match script {
                ScriptType::P2wpkh | ScriptType::P2shP2wpkh | ScriptType::P2pkh => true,
                ScriptType::P2tr => false,
            }
        }
        const fn touch_drawn(touch: TouchPolicy) -> bool {
            match touch {
                TouchPolicy::Always
                | TouchPolicy::Cached
                | TouchPolicy::AlwaysFixed
                | TouchPolicy::CachedFixed => true,
                TouchPolicy::Never => false,
            }
        }
        let scripts = [
            ScriptType::P2wpkh,
            ScriptType::P2shP2wpkh,
            ScriptType::P2pkh,
            ScriptType::P2tr,
        ];
        let touches = [
            TouchPolicy::Never,
            TouchPolicy::Always,
            TouchPolicy::Cached,
            TouchPolicy::AlwaysFixed,
            TouchPolicy::CachedFixed,
        ];
        let controls = ControlSet::default();
        // (press, drawn)
        let mut cases: Vec<(Press, bool)> = Vec::new();
        // Values with no row: every one is drawn but the Taproot scripts and `Never`.
        for key in [PgpKey::Sig, PgpKey::Aut] {
            for press in [
                YkPress::PgpNone(key),
                YkPress::PgpEvm(key),
                YkPress::PgpBtc(key),
                YkPress::PgpShared(key),
                YkPress::PgpZec(key),
            ] {
                cases.push((Press::Yk(press), true));
            }
            for script in scripts {
                cases.push((
                    Press::Yk(YkPress::PgpScript(key, script)),
                    script_drawn(script),
                ));
                cases.push((
                    Press::YkManage(YkManagePress::ReslotScript(key, script)),
                    script_drawn(script),
                ));
            }
            for touch in touches {
                cases.push((Press::Yk(YkPress::PgpTouch(key, touch)), touch_drawn(touch)));
            }
            for network in ZecNetwork::ALL {
                cases.push((Press::Yk(YkPress::PgpZecNetwork(key, network)), true));
            }
            for press in [
                YkManagePress::ReslotEvm(key),
                YkManagePress::ReslotBtc(key),
                YkManagePress::ReslotZec(key),
                YkManagePress::ReslotShared(key),
            ] {
                cases.push((Press::YkManage(press), true));
            }
        }
        for press in [
            CorePress::Lang(Lang::Ko),
            CorePress::Lang(Lang::En),
            CorePress::Template(RpcTemplate::QuickNode),
            CorePress::Template(RpcTemplate::Alchemy),
            CorePress::Template(RpcTemplate::Manual),
            CorePress::LogLevel(LogLevel::Error),
            CorePress::LogLevel(LogLevel::Warn),
            CorePress::LogLevel(LogLevel::Info),
            CorePress::LogLevel(LogLevel::Debug),
            CorePress::MismatchCheck(None),
            CorePress::CopyToggle(None),
            CorePress::LocalhostToggle(None),
            CorePress::AutolaunchToggle(None),
            CorePress::OverwriteCheck(None),
        ] {
            cases.push((Press::Core(press), true));
        }
        for press in [
            EvmPress::SendAck(None),
            EvmPress::TokenHideZero(None),
            EvmPress::RepinCheck(None),
        ] {
            cases.push((Press::Evm(press), true));
        }
        // One id per row: the last row of the span is drawn, the row at the span is not.
        let single: [(u16, RowPress); 18] = [
            (evm::SEND_ASSET_SPAN, |row| {
                Press::Evm(EvmPress::SendAsset(row))
            }),
            (evm::TOKEN_SEND_SPAN, |row| {
                Press::Evm(EvmPress::TokenSend(row))
            }),
            (evm::TOKEN_COPY_SPAN, |row| {
                Press::Evm(EvmPress::TokenCopy(row))
            }),
            (evm::SEND_PICK_SPAN, |row| {
                Press::Evm(EvmPress::PickRecipient(row))
            }),
            (evm::CAPS_CHAIN_SPAN, |row| {
                Press::Evm(EvmPress::CapsChain(row))
            }),
            (evm::TOKEN_ROW_SPAN / evm::TOKEN_ROW_STRIDE, |row| {
                Press::Evm(EvmPress::TokenToggleHidden(row))
            }),
            (evm::TOKEN_ROW_SPAN / evm::TOKEN_ROW_STRIDE, |row| {
                Press::Evm(EvmPress::TokenDelete(row))
            }),
            (yk::BACKUP_SPAN, |row| Press::Yk(YkPress::Backup(row))),
            (yk::REMOVE_SPAN, |row| Press::Yk(YkPress::Remove(row))),
            (yk::RENAME_CARD_SPAN, |row| {
                Press::Yk(YkPress::RenameCard(row))
            }),
            (yk::PINS_SPAN, |row| Press::Yk(YkPress::Pins(row))),
            (yk::PIN_GATE_SPAN, |row| Press::Yk(YkPress::PinGate(row))),
            (yk::RESLOT_SPAN, |row| {
                Press::YkManage(YkManagePress::Reslot(row))
            }),
            (yk::CLEAR_SPAN, |row| {
                Press::YkManage(YkManagePress::Clear(row))
            }),
            (yk::RESLOT_BACKUP_SPAN, |row| {
                Press::YkManage(YkManagePress::ReslotBackup(row))
            }),
            (core::NETWORK_SPAN, |row| {
                Press::Core(CorePress::Network(row))
            }),
            (core::ACCOUNT_SPAN, |row| {
                Press::Core(CorePress::Account(row))
            }),
            (core::RPC_ROW_OPEN_SPAN, |row| {
                Press::Core(CorePress::RpcRowOpen(row))
            }),
        ];
        for (rows, press) in single {
            cases.push((press(Row(rows - 1)), true));
            cases.push((press(Row(rows)), false));
        }
        // Several ids per row: an action is drawn while its offset is inside the span, so the
        // two rows around the span's end cover a partly drawn row and an undrawn one.
        let around = |span: u16, stride: u16| {
            let last = span.div_ceil(stride);
            [last - 1, last]
        };
        let chain_actions = [
            ChainRowAction::Edit,
            ChainRowAction::Delete,
            ChainRowAction::Repin,
        ];
        for row in around(evm::CHAIN_ROW_SPAN, 3) {
            for (offset, action) in (0..).zip(chain_actions) {
                cases.push((
                    Press::Evm(EvmPress::ChainRow(Row(row), action)),
                    row * 3 + offset < evm::CHAIN_ROW_SPAN,
                ));
            }
        }
        let activity_actions = [
            EvmActivityAction::CopyHash,
            EvmActivityAction::SpeedUp,
            EvmActivityAction::Cancel,
            EvmActivityAction::Resend,
            EvmActivityAction::Discard,
            EvmActivityAction::CopyExplorerLink,
            EvmActivityAction::SaveAddress,
            EvmActivityAction::OpenExplorer,
        ];
        for row in around(evm::ACTIVITY_SPAN, evm::ACTIVITY_STRIDE) {
            for (offset, action) in (0..).zip(activity_actions) {
                cases.push((
                    Press::Evm(EvmPress::Activity(Row(row), action)),
                    row * evm::ACTIVITY_STRIDE + offset < evm::ACTIVITY_SPAN,
                ));
            }
        }
        let rpc_actions = [
            RpcRowAction::Replace,
            RpcRowAction::Test,
            RpcRowAction::Delete,
        ];
        for row in around(core::ROW_SPAN, 3) {
            for (offset, action) in (0..).zip(rpc_actions) {
                cases.push((
                    Press::Core(CorePress::RpcRow(Row(row), action)),
                    row * 3 + offset < core::ROW_SPAN,
                ));
            }
        }
        for row in around(yk::CONNECT_CHOICE_SPAN, yk::CONNECT_CHOICE_STRIDE) {
            let inside = row < yk::CONNECT_CHOICE_ROWS;
            for press in [
                YkConnectPress::ChoiceEvm(Row(row)),
                YkConnectPress::ChoiceZec(Row(row)),
                YkConnectPress::ChoiceSol(Row(row)),
                YkConnectPress::ChoiceSkip(Row(row)),
            ] {
                cases.push((Press::YkConnect(press), inside));
            }
            for script in scripts {
                cases.push((
                    Press::YkConnect(YkConnectPress::ChoiceBtc(Row(row), script)),
                    inside && script_drawn(script),
                ));
            }
        }
        let mut undrawn = 0;
        for (press, drawn) in cases {
            let back = press_of(id_of(press), &controls);
            assert_eq!(back == Some(press), drawn, "{press:?} -> {back:?}");
            undrawn += usize::from(!drawn);
        }
        // Two slots x (two Taproot radios + `Never`); the 18 one-id rows at their span; chain
        // row 46 `Repin` and row 47; activity row 50; URL row 53 `Test`/`Delete` and row 54;
        // connect row 25's Taproot radio and all eight presses of row 26.
        assert_eq!(undrawn, 6 + 18 + (1 + 3) + 8 + (2 + 3) + (1 + 8));
    }

    /// S3 C12: after the last family, no control a click can send is legacy any more except
    /// the ones no handler claimed before either: the edits (fields and credentials), S22's
    /// painted hold area and the eighth id of a `YubiKey` connect choice row. Table tests (2)
    /// and (7) (S3 D3): `Legacy` is gone, and exactly these ids are no press (`None`); an id
    /// past every block is none either. 2026-11-18 (S3 D1-D3 review): no such id is a
    /// `새로고침` or a receive-gated id, so dropping `Press::Legacy`'s receive gate and the
    /// received-history observer it reached (`App::received_observe`) loses nothing.
    #[test]
    fn only_unclaimed_ids_are_no_press() {
        use screens_yubikey::ids::{
            CONNECT_CHOICE_BASE, CONNECT_CHOICE_SPAN, CONNECT_CHOICE_STRIDE,
        };
        let controls = ControlSet::default();
        for id in every_id() {
            let no_radio = id.checked_sub(CONNECT_CHOICE_BASE).is_some_and(|offset| {
                offset < CONNECT_CHOICE_SPAN && offset % CONNECT_CHOICE_STRIDE == 7
            });
            let unclaimed = field_of(id).is_some()
                || cred_of(id).is_some()
                || id == screens_reset::ids::RESET_HOLD
                || no_radio;
            let none = press_of(id, &controls).is_none();
            assert_eq!(none, unclaimed, "{id}");
            if none {
                assert_eq!(crate::app_received::refresh_chain(id), None, "{id}");
                assert!(!screens::RECEIVE_IDS.contains(&id), "{id}");
            }
        }
        // An id in no block of `ui::command_ids` (not every decoded block is listed there, e.g.
        // Zcash's source radios at 8 020, so only ids past the last block are checked).
        for id in [IDCANCEL + 1, 60_000, u16::MAX] {
            assert_eq!(press_of(id, &controls), None, "{id}");
        }
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
        let mut input = capture(ids::TPL_SAVE, &controls, None, "");
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
        let mut plain = capture(screens_llm::ids::SAVE, &controls, None, "");
        assert!(format!("{plain:?}").starts_with("PressInput { creds: []"));
        assert!(plain.take(CredField::LlmKey).is_empty());
        #[cfg(debug_assertions)]
        assert_eq!(plain.misses(), 1);
        controls.type_text(screens_llm::ids::KEY_EDIT, &"k".repeat(1_100));
        let mut key = capture(screens_llm::ids::KEY_SAVE, &controls, None, "");
        assert_eq!(key.take(CredField::LlmKey).len(), CredField::LlmKey.cap());
    }

    /// S3 D1: only the two `WalletConnect` clipboard presses carry a clipboard input, and
    /// without a main window it is `NoWindow` (nothing is read: no clipboard access headless).
    /// 2026-11-20 (S4 P5): only `이미지 파일에서 QR 읽기` carries an image input; with no path
    /// (no edit, an empty kept path) it is `NoPath` and no file is opened.
    #[test]
    fn capture_reads_the_clipboard_only_for_its_two_presses() {
        use crate::ui::screens_walletconnect::ids as wc;
        let controls = ControlSet::default();
        for id in [wc::CLIPBOARD_CONNECT, wc::CLIPBOARD_QR] {
            let mut input = capture(id, &controls, None, "");
            assert!(matches!(input.take_clip(), Some(ClipInput::NoWindow)));
            #[cfg(debug_assertions)]
            assert_eq!(input.misses(), 0);
        }
        let mut file = capture(wc::FILE_QR, &controls, None, "");
        assert!(matches!(file.take_image(), Some(ImageInput::NoPath)));
        #[cfg(debug_assertions)]
        assert_eq!(file.misses(), 0);
        for id in every_id() {
            let shown = format!("{:?}", capture(id, &controls, None, ""));
            if id != wc::CLIPBOARD_CONNECT && id != wc::CLIPBOARD_QR {
                assert!(!shown.contains("clip"), "{id}: {shown}");
            }
            if id != wc::FILE_QR {
                assert!(!shown.contains("image"), "{id}: {shown}");
            }
        }
    }

    /// S4 P5 (spec/13 §6): the image-file press reads the path edit (else the kept path), trims
    /// spaces and Explorer's quotes, refuses a missing file, a folder and a file without a
    /// PNG/JPEG/BMP/GIF signature before any decoder sees it, gives `Unreadable` when GDI+ cannot
    /// decode an accepted file, and the decoded pixels of a BMP. Files only in the test's own
    /// temp folder (removed at the end).
    #[test]
    fn capture_reads_the_image_file_in_the_shell() {
        use crate::ui::screens_walletconnect::ids as wc;
        let dir = std::env::temp_dir().join(format!("yw-p5-capture-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bmp = dir.join("two.bmp");
        std::fs::write(&bmp, bmp_2x1()).unwrap();
        let text = dir.join("note.txt");
        std::fs::write(&text, b"not an image at all").unwrap();
        let broken = dir.join("broken.png");
        std::fs::write(&broken, b"\x89PNG\r\n\x1a\nbroken").unwrap();
        let shown = |field: Option<&str>, kept: &str| {
            let controls = ControlSet::default();
            if let Some(field) = field {
                controls.type_text(wc::FILE_EDIT, field);
            }
            let mut input = capture(wc::FILE_QR, &controls, None, kept);
            let image = input.take_image();
            #[cfg(debug_assertions)]
            assert_eq!(input.misses(), 0);
            format!("{image:?}")
        };
        let bmp_text = bmp.display().to_string();
        let quoted = format!("  \"{bmp_text}\" ");
        assert_eq!(shown(Some(&quoted), ""), "Some(Pixels(2, 1, 8))");
        // The kept path only when the edit does not exist; an empty edit is an empty path.
        assert_eq!(shown(None, &bmp_text), "Some(Pixels(2, 1, 8))");
        assert_eq!(shown(Some("  "), &bmp_text), "Some(NoPath)");
        assert_eq!(shown(Some("\"\""), ""), "Some(NoPath)");
        let missing = dir.join("missing.png").display().to_string();
        let folder = dir.display().to_string();
        let note = text.display().to_string();
        for refused in [&missing, &folder, &note] {
            assert_eq!(shown(Some(refused), ""), "Some(Refused)", "{refused}");
        }
        let broken = broken.display().to_string();
        assert_eq!(shown(Some(&broken), ""), "Some(Unreadable)");
        // The decoded pixels are B, G, R, A, top row first.
        let controls = ControlSet::default();
        controls.type_text(wc::FILE_EDIT, &bmp_text);
        let mut input = capture(wc::FILE_QR, &controls, None, "");
        assert!(matches!(
            input.take_image(),
            Some(ImageInput::Pixels { pixels, .. })
                if pixels.as_slice() == [0, 0, 255, 255, 255, 255, 255, 255]
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A 2×1 24-bit bottom-up BMP: a red pixel, then a white one.
    fn bmp_2x1() -> Vec<u8> {
        let mut file = Vec::new();
        file.extend_from_slice(b"BM");
        file.extend_from_slice(&62_u32.to_le_bytes()); // file size: 14 + 40 + 8
        file.extend_from_slice(&[0; 4]);
        file.extend_from_slice(&54_u32.to_le_bytes()); // pixel data offset
        file.extend_from_slice(&40_u32.to_le_bytes()); // BITMAPINFOHEADER
        file.extend_from_slice(&2_i32.to_le_bytes());
        file.extend_from_slice(&1_i32.to_le_bytes());
        file.extend_from_slice(&1_u16.to_le_bytes()); // planes
        file.extend_from_slice(&24_u16.to_le_bytes()); // bits per pixel
        file.extend_from_slice(&[0; 24]); // BI_RGB, sizes, resolution, palette
        file.extend_from_slice(&[0, 0, 255, 255, 255, 255, 0, 0]); // B G R, B G R, row padding
        file
    }

    /// S3 D1 (spec/13 §6): a copied pairing link becomes the press's link (whole, leading
    /// whitespace kept for the handler's `trim`, as before); any other text gives nothing, so it
    /// is never copied out of the clipboard's wiped buffer.
    #[test]
    fn clip_link_takes_pairing_links_only() {
        let units = |text: &str| text.encode_utf16().collect::<Vec<u16>>();
        for link in [
            "wc:abc@2?relay-protocol=irn&symKey=00",
            "  \twc:abc@2",
            "WC:abc@2",
            "wc%3Aabc%402",
            "Wc%3aabc",
        ] {
            let got = clip_link(&units(link));
            assert_eq!(got.as_deref().map(String::as_str), Some(link), "{link}");
        }
        for other in [
            "",
            "   ",
            "w",
            "wc",
            "wc;abc",
            "my wallet password",
            "x wc:abc@2",
            "\u{FF57}c:abc",
        ] {
            assert!(clip_link(&units(other)).is_none(), "{other:?}");
        }
        // A lone surrogate before the link is not whitespace: not a link.
        assert!(clip_link(&[0xD800, u16::from(b'w'), u16::from(b'c'), u16::from(b':')]).is_none());
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
