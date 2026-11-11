//! Block explorer controls (2026-11-11, spec/04 §2.6, §2.11 "블록 탐색기"): the command ids, the
//! S15 card "블록 탐색기" (네트워크(RPC) section, after "네트워크별 RPC 주소") and the small
//! button rows other screens add next to a hash or an address. The logic is `app_explorer`.

use crate::app::App;
use crate::explorer::{ExplorerNet, LinkKind, TEMPLATE_MAX_BYTES};
use crate::ui::main_window::{Ctl, Item, Tone};

/// Command ids (17,200–17,709; the whole map is `ui::command_ids`).
pub mod ids {
    /// S15 card: the transaction template field.
    pub const EDIT_TX: u16 = 17_200;
    /// S15 card: the address template field.
    pub const EDIT_ADDRESS: u16 = 17_201;
    /// S15 card: `저장`.
    pub const SAVE: u16 = 17_202;
    /// S15 card: `취소`.
    pub const CANCEL: u16 = 17_203;
    /// EVM account card `탐색기에서 주소 보기`.
    pub const CARD_EVM: u16 = 17_204;
    /// Solana account card `탐색기에서 주소 보기`.
    pub const CARD_SOL: u16 = 17_205;
    /// Bitcoin account card `탐색기에서 주소 보기`.
    pub const CARD_BTC: u16 = 17_206;
    /// Zcash account card `탐색기에서 주소 보기`.
    pub const CARD_ZEC: u16 = 17_207;
    /// `HyperCore` card `탐색기에서 주소 보기`.
    pub const CARD_HC: u16 = 17_208;
    /// EVM send result `탐색기에서 열기`.
    pub const RESULT_EVM_OPEN: u16 = 17_210;
    /// EVM send result `탐색기 링크 복사`.
    pub const RESULT_EVM_COPY: u16 = 17_211;
    /// Solana send result `탐색기에서 열기`.
    pub const RESULT_SOL_OPEN: u16 = 17_212;
    /// Solana send result `탐색기 링크 복사`.
    pub const RESULT_SOL_COPY: u16 = 17_213;
    /// Bitcoin send result `탐색기에서 열기`.
    pub const RESULT_BTC_OPEN: u16 = 17_214;
    /// Bitcoin send result `탐색기 링크 복사`.
    pub const RESULT_BTC_COPY: u16 = 17_215;
    /// Zcash send result line `탐색기에서 열기`.
    pub const RESULT_ZEC_OPEN: u16 = 17_216;
    /// Zcash send result line `탐색기 링크 복사`.
    pub const RESULT_ZEC_COPY: u16 = 17_217;
    /// S15 card rows ([`ROW_STRIDE`] ids per row: `변경`, `기본값으로`), in
    /// `App::explorer_networks` order.
    pub const ROW_BASE: u16 = 17_220;
    /// Ids per card row.
    pub const ROW_STRIDE: u16 = 2;
    /// Card rows span (50 rows × 2; at most 7 + 32 + 2 + 2 + 2 + 2 = 47 networks).
    pub const ROW_SPAN: u16 = 100;
    /// Ids per activity row (`탐색기에서 열기`, `탐색기 링크 복사`).
    pub const ACTIVITY_STRIDE: u16 = 2;
    /// Solana activity rows (display order, as `App::sol_activity_tx_ids`).
    pub const SOL_ACTIVITY_BASE: u16 = 17_320;
    /// Solana activity span (64 rows × 2).
    pub const SOL_ACTIVITY_SPAN: u16 = 128;
    /// Bitcoin activity rows (display order, as `BtcUi::activity_rows`).
    pub const BTC_ACTIVITY_BASE: u16 = 17_450;
    /// Bitcoin activity span (50 rows × 2).
    pub const BTC_ACTIVITY_SPAN: u16 = 100;
    /// Zcash activity rows (newest first, as drawn).
    pub const ZEC_ACTIVITY_BASE: u16 = 17_550;
    /// Zcash activity span (80 rows × 2).
    pub const ZEC_ACTIVITY_SPAN: u16 = 160;

    const _: () = assert!(RESULT_ZEC_COPY < ROW_BASE);
    const _: () = assert!(ROW_BASE + ROW_SPAN <= SOL_ACTIVITY_BASE);
    const _: () = assert!(SOL_ACTIVITY_BASE + SOL_ACTIVITY_SPAN <= BTC_ACTIVITY_BASE);
    const _: () = assert!(BTC_ACTIVITY_BASE + BTC_ACTIVITY_SPAN <= ZEC_ACTIVITY_BASE);
    const _: () = assert!(ZEC_ACTIVITY_BASE + ZEC_ACTIVITY_SPAN <= 17_710);

    /// Every fixed id (`ui::command_ids` checks them against all ranges).
    pub const FIXED: &[u16] = &[
        EDIT_TX,
        EDIT_ADDRESS,
        SAVE,
        CANCEL,
        CARD_EVM,
        CARD_SOL,
        CARD_BTC,
        CARD_ZEC,
        CARD_HC,
        RESULT_EVM_OPEN,
        RESULT_EVM_COPY,
        RESULT_SOL_OPEN,
        RESULT_SOL_COPY,
        RESULT_BTC_OPEN,
        RESULT_BTC_COPY,
        RESULT_ZEC_OPEN,
        RESULT_ZEC_COPY,
    ];

    /// The two ids of activity row `row` of a list starting at `base` (`None` past `span`).
    #[must_use]
    pub fn activity_ids(base: u16, span: u16, row: usize) -> Option<(u16, u16)> {
        let offset = u16::try_from(row).ok()?.checked_mul(ACTIVITY_STRIDE)?;
        (offset.checked_add(1)? < span).then(|| {
            let open = base.saturating_add(offset);
            (open, open.saturating_add(1))
        })
    }
}

/// The S15 card's help (what it is for and what leaves the PC).
pub const T_EXPLORER_CARD: &str = "활동·보내기 결과의 '탐색기에서 열기'와 계정 카드의 '탐색기에서 주소 보기'가 기본 브라우저로 여는 주소입니다. 거래 해시와 주소는 공개 정보지만, 여는 순간 그 사이트는 내 IP와 함께 그 거래·주소를 봅니다. 앱은 탐색기 페이지를 읽지 않습니다.";
/// The rules under the open form.
pub const T_EXPLORER_RULES: &str = "https:// 로 시작하고 거래 페이지에는 {hash}, 주소 페이지에는 {address}를 한 번씩 넣으세요(예: https://etherscan.io/tx/{hash}). 비워 두면 기본값을 씁니다. 256자 이하, 영문·숫자와 - . _ ~ : / ? & = + 만 쓸 수 있습니다(사용자 정보 …@·# 뒤 부분 없음).";

impl App {
    /// `탐색기에서 열기` and `탐색기 링크 복사` for `hash` on `network` (empty when there is no
    /// URL: no template, or a hash outside the network's character set).
    #[must_use]
    pub fn explorer_tx_buttons(
        &self,
        network: impl Into<ExplorerNet>,
        hash: &str,
        ids: Option<(u16, u16)>,
    ) -> Vec<Ctl> {
        match ids {
            Some((open, copy)) if self.explorer_tx_url(network, hash).is_some() => vec![
                Ctl::button(open, "탐색기에서 열기"),
                Ctl::button(copy, "탐색기 링크 복사"),
            ],
            _ => Vec::new(),
        }
    }

    /// The account card's small `탐색기에서 주소 보기` (`None` without an address page).
    #[must_use]
    pub fn explorer_address_link(
        &self,
        network: impl Into<ExplorerNet>,
        address: &str,
        id: u16,
    ) -> Option<Ctl> {
        self.explorer_address_url(network, address)
            .map(|_| Ctl::link(id, "탐색기에서 주소 보기").compact())
    }

    /// An account card's address line ([`crate::ui::screens::own_address_row`]) with its
    /// `탐색기에서 주소 보기` (`card`) when `network` has an address page.
    #[must_use]
    pub fn own_address_line(
        &self,
        network: impl Into<ExplorerNet>,
        address: &str,
        kind: crate::ui::theme::AddressKind,
        copy: u16,
        enabled: bool,
        card: u16,
    ) -> Item {
        crate::ui::screens::own_address_row(
            address,
            kind,
            copy,
            enabled,
            self.explorer_address_link(network, address, card),
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
        match used.get(kind) {
            None => format!("{}: 없음", kind.label()),
            Some(template) if overridden => format!("{}: {template} · 사용자 지정", kind.label()),
            Some(template) if from_chain => {
                format!("{}: {template} · 기본(체인 등록 값)", kind.label())
            }
            Some(template) => format!("{}: {template} · 기본", kind.label()),
        }
    }

    /// The S15 card "블록 탐색기" (네트워크(RPC) section): one row per network with the
    /// templates in use, `변경` (an inline form with both templates) and `기본값으로`.
    pub fn explorer_settings_card(&self, items: &mut Vec<Item>) {
        items.push(Item::CardStart(Some("블록 탐색기".to_owned())));
        items.push(Item::Help(T_EXPLORER_CARD.to_owned()));
        let networks = self.explorer_networks();
        let last = networks.len().saturating_sub(1);
        for (row, net) in networks.into_iter().enumerate() {
            items.push(Item::Text(format!(
                "{}  ({net})",
                self.explorer_net_name(net)
            )));
            items.push(Item::Help(self.explorer_line(net, LinkKind::Tx)));
            items.push(Item::Help(self.explorer_line(net, LinkKind::Address)));
            let base = ids::ROW_BASE.saturating_add(
                u16::try_from(row)
                    .unwrap_or(0)
                    .saturating_mul(ids::ROW_STRIDE),
            );
            let editing = self.explorer_ui.editing == Some(net);
            items.push(Item::Row(vec![
                Ctl::button(base, "변경").compact().enabled(!editing),
                Ctl::button(base.saturating_add(1), "기본값으로")
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
        let limit = u32::try_from(TEMPLATE_MAX_BYTES).unwrap_or(256);
        items.push(Item::LabeledRow(
            LinkKind::Tx.label().to_owned(),
            vec![Ctl::edit(
                ids::EDIT_TX,
                &self.explorer_ui.tx_text,
                430,
                false,
                limit,
            )],
        ));
        items.push(Item::LabeledRow(
            LinkKind::Address.label().to_owned(),
            vec![Ctl::edit(
                ids::EDIT_ADDRESS,
                &self.explorer_ui.address_text,
                430,
                false,
                limit,
            )],
        ));
        items.push(Item::Help(T_EXPLORER_RULES.to_owned()));
        if let Some(message) = &self.explorer_ui.message {
            items.push(Item::Banner(message.clone(), Tone::Danger));
        }
        items.push(Item::Row(vec![
            Ctl::primary(ids::SAVE, "저장"),
            Ctl::button(ids::CANCEL, "취소"),
        ]));
    }
}

#[cfg(test)]
mod tests {
    use super::ids::{
        ACTIVITY_STRIDE, BTC_ACTIVITY_BASE, BTC_ACTIVITY_SPAN, ZEC_ACTIVITY_BASE,
        ZEC_ACTIVITY_SPAN, activity_ids,
    };

    #[test]
    fn activity_ids_stay_in_their_span() {
        assert_eq!(
            activity_ids(BTC_ACTIVITY_BASE, BTC_ACTIVITY_SPAN, 0),
            Some((BTC_ACTIVITY_BASE, BTC_ACTIVITY_BASE + 1))
        );
        let last = usize::from(BTC_ACTIVITY_SPAN / ACTIVITY_STRIDE) - 1;
        assert_eq!(
            activity_ids(BTC_ACTIVITY_BASE, BTC_ACTIVITY_SPAN, last),
            Some((BTC_ACTIVITY_BASE + 98, BTC_ACTIVITY_BASE + 99))
        );
        assert_eq!(
            activity_ids(BTC_ACTIVITY_BASE, BTC_ACTIVITY_SPAN, last + 1),
            None
        );
        assert_eq!(
            activity_ids(ZEC_ACTIVITY_BASE, ZEC_ACTIVITY_SPAN, 79),
            Some((ZEC_ACTIVITY_BASE + 158, ZEC_ACTIVITY_BASE + 159))
        );
    }
}
