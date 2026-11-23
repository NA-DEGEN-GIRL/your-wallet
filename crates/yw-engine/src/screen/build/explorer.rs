//! Block explorer controls (2026-11-11, spec/04 §2.6, §2.11 "블록 탐색기"): the command ids, the
//! S15 card "블록 탐색기" (네트워크(RPC) section, after "네트워크별 RPC 주소") and the small
//! button rows other screens add next to a hash or an address. The logic is `app_explorer`.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): moved here from yw-app `ui/screens_explorer.rs` with the
//! bodies unchanged (`impl App` builders became `impl Screen<'_>`, yw-app paths engine paths); its
//! control ids stay there (`ui::screens_explorer::ids`).

use super::Screen;
use crate::cmd::{ExplorerLinkAction, ExplorerPress, ExplorerRowAction, Press, Row};
use crate::explorer::{ExplorerNet, LinkKind, TEMPLATE_MAX_BYTES};
use crate::form::EditField;
use crate::screen::Tone;
use crate::screen::model::{Ctl, GLYPH_OPEN, Item};

/// S15 explorer texts (spec/04 §2.11, §2.14; English spec/14 §5).
pub mod text {
    yw_core::texts! {
        /// The S15 card's help (what it is for and what leaves the PC).
        EXPLORER_CARD = "활동·보내기 결과의 '탐색기에서 열기'와 계정 카드의 '탐색기에서 주소 보기'가 기본 브라우저로 여는 주소입니다. 거래 해시와 주소는 공개 정보지만, 여는 순간 그 사이트는 내 IP와 함께 그 거래·주소를 봅니다. 앱은 탐색기 페이지를 읽지 않습니다."
            / "The addresses that 'Open in explorer' (activity, send result) and 'View address in explorer' (account cards) open in your default browser. Transaction hashes and addresses are public, but the moment you open one, that site sees the transaction or address together with your IP. The app never reads explorer pages.";
        /// The rules under the open form.
        EXPLORER_RULES = "https:// 로 시작하고 거래 페이지에는 {hash}, 주소 페이지에는 {address}를 한 번씩 넣으세요(예: https://etherscan.io/tx/{hash}). 비워 두면 기본값을 씁니다. 256자 이하, 영문·숫자와 - . _ ~ : / ? & = + 만 쓸 수 있습니다(사용자 정보 …@·# 뒤 부분 없음)."
            / "Start with https:// and put {hash} once in the transaction page and {address} once in the address page (e.g. https://etherscan.io/tx/{hash}). Leave empty to use the default. Up to 256 characters; only letters, digits and - . _ ~ : / ? & = + (no user info …@, nothing after #).";
        OPEN = "탐색기에서 열기" / "Open in explorer";
        COPY_LINK = "탐색기 링크 복사" / "Copy explorer link";
        VIEW_ADDRESS = "탐색기에서 주소 보기" / "View address in explorer";
        LINE_NONE(1) = "{0}: 없음" / "{0}: none";
        LINE_CUSTOM(2) = "{0}: {1} · 사용자 지정" / "{0}: {1} · custom";
        LINE_CHAIN_DEFAULT(2) = "{0}: {1} · 기본(체인 등록 값)" / "{0}: {1} · default (from the chain entry)";
        LINE_DEFAULT(2) = "{0}: {1} · 기본" / "{0}: {1} · default";
        CARD_TITLE = "블록 탐색기" / "Block explorer";
        CHANGE = "변경" / "Change";
        RESET = "기본값으로" / "Reset";
        SAVE = "저장" / "Save";
        CANCEL = "취소" / "Cancel";
    }
}

/// The `탐색기에서 열기` and `탐색기 링크 복사` presses of activity row `row` (`link`: a chain's
/// `ExplorerPress::*Activity`; `None` past `rows`, `crate::screen::rows::*_ACTIVITY_LINKS`).
/// 2026-11-24 (spec/15 §11.4 S5-4): before, the two control ids `ids::activity_ids(base, span,
/// row)`.
#[must_use]
pub fn activity_links(
    link: fn(Row, ExplorerLinkAction) -> ExplorerPress,
    row: usize,
    rows: u16,
) -> Option<(Press, Press)> {
    crate::screen::rows::row(row, rows).map(|row| {
        (
            link(row, ExplorerLinkAction::Open).into(),
            link(row, ExplorerLinkAction::Copy).into(),
        )
    })
}

impl Screen<'_> {
    /// `탐색기에서 열기` and `탐색기 링크 복사` for `hash` on `network` (empty when there is no
    /// URL: no template, or a hash outside the network's character set).
    #[must_use]
    pub fn explorer_tx_buttons(
        &self,
        network: impl Into<ExplorerNet>,
        hash: &str,
        presses: Option<(Press, Press)>,
    ) -> Vec<Ctl> {
        match presses {
            Some((open, copy)) if self.explorer_tx_url(network, hash).is_some() => vec![
                Ctl::button(open, text::OPEN.get(self.settings.language)),
                Ctl::button(copy, text::COPY_LINK.get(self.settings.language)),
            ],
            _ => Vec::new(),
        }
    }

    /// The small `탐색기에서 주소 보기` link (the `HyperCore` card; `None` without an address
    /// page).
    #[must_use]
    pub fn explorer_address_link(
        &self,
        network: impl Into<ExplorerNet>,
        address: &str,
        press: impl Into<Press>,
    ) -> Option<Ctl> {
        self.explorer_address_url(network, address).map(|_| {
            Ctl::link(press.into(), text::VIEW_ADDRESS.get(self.settings.language)).compact()
        })
    }

    /// The account card's ↗ icon `탐색기에서 주소 보기` on its address line (2026-11-11; `None`
    /// without an address page).
    #[must_use]
    pub fn explorer_address_icon(
        &self,
        network: impl Into<ExplorerNet>,
        address: &str,
        press: impl Into<Press>,
    ) -> Option<Ctl> {
        self.explorer_address_url(network, address).map(|_| {
            Ctl::icon(
                press.into(),
                GLYPH_OPEN,
                text::VIEW_ADDRESS.get(self.settings.language),
            )
        })
    }

    /// An account card's address line ([`crate::screen::build::core::own_address_row`]) with its ↗
    /// `탐색기에서 주소 보기` (`card`) when `network` has an address page.
    #[must_use]
    pub fn own_address_line(
        &self,
        network: impl Into<ExplorerNet>,
        address: &str,
        kind: crate::screen::address::AddressKind,
        copy: impl Into<Press>,
        enabled: bool,
        card: impl Into<Press>,
    ) -> Item {
        crate::screen::build::core::own_address_row(
            self.settings.language,
            address,
            kind,
            copy,
            enabled,
            self.explorer_address_icon(network, address, card),
        )
    }

    /// One template line of a card row: the template (or `없음`) and where it comes from.
    fn explorer_line(&self, net: ExplorerNet, kind: LinkKind) -> String {
        let used = self.explorer_templates(net);
        let overridden = self
            .explorer_override(net)
            .is_some_and(|entry| entry.templates.get(kind).is_some());
        let from_chain = matches!(net, ExplorerNet::Evm(id)
            if self.settings.evm_chains.iter().any(|chain| chain.chain_id == id && chain.explorer.is_some()));
        let lang = self.settings.language;
        let label = kind.label_in(lang);
        match used.get(kind) {
            None => text::LINE_NONE.fill(lang, [label]),
            Some(template) if overridden => text::LINE_CUSTOM.fill(lang, [label, template]),
            Some(template) if from_chain => text::LINE_CHAIN_DEFAULT.fill(lang, [label, template]),
            Some(template) => text::LINE_DEFAULT.fill(lang, [label, template]),
        }
    }

    /// The S15 card "블록 탐색기" (네트워크(RPC) section): one row per network with the
    /// templates in use, `변경` (an inline form with both templates) and `기본값으로`.
    pub fn explorer_settings_card(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::CardStart(Some(text::CARD_TITLE.get(lang).to_owned())));
        items.push(Item::Help(text::EXPLORER_CARD.get(lang).to_owned()));
        let networks = self.explorer_networks();
        let last = networks.len().saturating_sub(1);
        for (row, net) in networks.into_iter().enumerate() {
            items.push(Item::Text(format!(
                "{}  ({net})",
                self.explorer_net_name(net)
            )));
            items.push(Item::Help(self.explorer_line(net, LinkKind::Tx)));
            items.push(Item::Help(self.explorer_line(net, LinkKind::Address)));
            let row_press = Row(u16::try_from(row).unwrap_or(0));
            let editing = self.explorer_ui.editing == Some(net);
            items.push(Item::Row(vec![
                Ctl::button(
                    ExplorerPress::Row(row_press, ExplorerRowAction::Edit),
                    text::CHANGE.get(lang),
                )
                .compact()
                .enabled(!editing),
                Ctl::button(
                    ExplorerPress::Row(row_press, ExplorerRowAction::Reset),
                    text::RESET.get(lang),
                )
                .compact()
                .enabled(self.explorer_override(net).is_some()),
            ]));
            if editing {
                self.explorer_form(items);
            }
            if row != last {
                items.push(Item::Rule);
            }
        }
        items.push(Item::CardEnd);
    }

    fn explorer_form(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let limit = u32::try_from(TEMPLATE_MAX_BYTES).unwrap_or(256);
        items.push(Item::LabeledRow(
            LinkKind::Tx.label_in(lang).to_owned(),
            vec![Ctl::edit(
                EditField::ExplorerTx,
                &self.explorer_ui.tx_text,
                430,
                false,
                limit,
            )],
        ));
        items.push(Item::LabeledRow(
            LinkKind::Address.label_in(lang).to_owned(),
            vec![Ctl::edit(
                EditField::ExplorerAddress,
                &self.explorer_ui.address_text,
                430,
                false,
                limit,
            )],
        ));
        items.push(Item::Help(text::EXPLORER_RULES.get(lang).to_owned()));
        if let Some(message) = &self.explorer_ui.message {
            items.push(Item::Banner(message.clone(), Tone::Danger));
        }
        items.push(Item::Row(vec![
            Ctl::primary(ExplorerPress::Save, text::SAVE.get(lang)),
            Ctl::button(ExplorerPress::Cancel, text::CANCEL.get(lang)),
        ]));
    }
}
