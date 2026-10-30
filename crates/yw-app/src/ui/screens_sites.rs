//! S13 연결된 사이트 (spec/04 §2.9): every grant with its origin (http badge), accounts in return
//! order, origin chain and connection time; `연결 해제` per row and `모두 해제` (confirmation).
//! Solana and Bitcoin connections (spec/05 §4.9: ownership proof only) follow the EVM grants with
//! their own `연결 해제` rows; row ids count over the combined list.
//! Also the S07 T-UNLOCK-PENDING line (spec/04 §2.5, §2.16).

use core::fmt::Write as _;

use crate::app::{App, Confirm};
use crate::ui::main_window::{Ctl, Item, Tone};

/// Control ids (6,700–6,965; the whole map is `ui::command_ids`).
pub mod ids {
    /// 연결된 사이트.
    pub const SITES_OPEN: u16 = 6_700;
    /// 모두 해제.
    pub const SITES_REVOKE_ALL: u16 = 6_701;
    /// Row buttons (`연결 해제`), one per grant.
    pub const SITE_ROW_BASE: u16 = 6_710;
    /// Row span (256 grants, spec/02 §5.3).
    pub const SITE_ROW_SPAN: u16 = 256;
    /// Every fixed id of this module.
    pub const FIXED: &[u16] = &[SITES_OPEN, SITES_REVOKE_ALL];
}

fn row_id(index: usize) -> u16 {
    u16::try_from(index)
        .ok()
        .filter(|offset| *offset < ids::SITE_ROW_SPAN)
        .map_or(0, |offset| ids::SITE_ROW_BASE + offset)
}

fn local_time(unix_ms: u64) -> String {
    let local = yw_win::time::local_wall_ms(unix_ms);
    let text = crate::logging::format_utc(local.unwrap_or(unix_ms));
    let short = text.get(..16).unwrap_or(&text).replace('T', " ");
    if local.is_some() {
        short
    } else {
        format!("{short} UTC")
    }
}

impl App {
    /// S13.
    pub(crate) fn sites_screen(&self, items: &mut Vec<Item>) {
        items.push(crate::ui::screens::back_main());
        items.push(Item::Title("연결된 사이트".to_owned()));
        let grants = self.browser_grants();
        let (sol_grants, btc_grants) = self.chain_grants();
        items.push(Item::Help(
            "연결된 사이트는 선택한 계정의 주소, 잔액, 거래 기록을 볼 수 있습니다. 서명과 전송은 매번 따로 승인합니다."
                .to_owned(),
        ));
        if grants.is_empty() && sol_grants.is_empty() && btc_grants.is_empty() {
            items.push(Item::CardStart(None));
            items.push(Item::Subtitle("연결된 사이트가 없습니다".to_owned()));
            items.push(Item::Text(
                "dApp 사이트에서 '지갑 연결'을 누르고 이 앱의 연결 창에서 승인하면 여기에 표시됩니다."
                    .to_owned(),
            ));
            items.push(Item::CardEnd);
            return;
        }
        let labels = self.own_accounts();
        for (index, site) in grants.iter().enumerate() {
            items.push(Item::CardStart(Some(site.origin.as_str().to_owned())));
            if site.origin.is_http() {
                items.push(Item::Banner(
                    "로컬 개발 사이트(http)".to_owned(),
                    Tone::Warn,
                ));
            }
            let chain = self
                .settings
                .evm_chain_name(site.chain_id)
                .unwrap_or_else(|| format!("chainId {}", site.chain_id));
            items.push(Item::Field("네트워크".to_owned(), chain));
            items.push(Item::Field(
                "연결 시각".to_owned(),
                local_time(site.granted_at_unix_ms),
            ));
            items.push(Item::Field(
                "볼 수 있는 계정".to_owned(),
                format!("{}개", site.accounts.len()),
            ));
            for account in &site.accounts {
                let label = labels
                    .iter()
                    .find(|(address, _)| address == account)
                    .map_or("", |(_, label)| label.as_str());
                items.push(Item::Help(label.to_owned()));
                items.push(Item::Mono(yw_core::evm::display::format_address(account)));
            }
            let id = row_id(index);
            if id != 0 {
                items.push(Item::Row(vec![Ctl::danger(id, "연결 해제")]));
            }
            items.push(Item::CardEnd);
        }
        let mut index = grants.len();
        for grant in &sol_grants {
            items.push(Item::CardStart(Some(grant.origin.as_str().to_owned())));
            items.push(Item::Field(
                "네트워크".to_owned(),
                "Solana (메시지 서명·소유 증명만)".to_owned(),
            ));
            items.push(Item::Field(
                "연결 시각".to_owned(),
                local_time(grant.granted_at_unix_ms),
            ));
            items.push(Item::Mono(yw_core::codec::base58::base58_encode(
                &grant.public,
            )));
            let id = row_id(index);
            if id != 0 {
                items.push(Item::Row(vec![Ctl::danger(id, "연결 해제")]));
            }
            items.push(Item::CardEnd);
            index += 1;
        }
        for grant in &btc_grants {
            items.push(Item::CardStart(Some(grant.origin.as_str().to_owned())));
            items.push(Item::Field(
                "네트워크".to_owned(),
                format!("{} (메시지 서명·소유 증명만)", grant.network.display_name()),
            ));
            items.push(Item::Field(
                "연결 시각".to_owned(),
                local_time(grant.granted_at_unix_ms),
            ));
            for entry in &grant.addresses {
                items.push(Item::Help(entry.purpose.label().to_owned()));
                items.push(Item::Mono(entry.address.clone()));
            }
            let id = row_id(index);
            if id != 0 {
                items.push(Item::Row(vec![Ctl::danger(id, "연결 해제")]));
            }
            items.push(Item::CardEnd);
            index += 1;
        }
        items.push(Item::Row(vec![Ctl::danger(
            ids::SITES_REVOKE_ALL,
            "모든 사이트 연결 해제",
        )]));
    }

    /// S07 T-UNLOCK-PENDING (at most 5 origins, then "외 n건").
    pub(crate) fn unlock_pending_text(&self) -> Option<String> {
        let origins = self.waiting_origins();
        if origins.is_empty() {
            return None;
        }
        let count = self
            .evm
            .queue
            .waiting_payloads()
            .filter(|item| matches!(item, crate::app_evm::QueuedItem::Site(_)))
            .count();
        let shown: Vec<&str> = origins.iter().take(5).map(String::as_str).collect();
        let mut list = shown.join(", ");
        if origins.len() > 5 {
            let _ = write!(list, " 외 {}건", origins.len() - 5);
        }
        Some(format!("잠금 해제를 기다리는 요청 {count}건: {list}"))
    }

    /// Commands of S13.
    pub(crate) fn on_sites_command(&mut self, id: u16) -> bool {
        match id {
            ids::SITES_OPEN => {
                self.set_screen(crate::app::Screen::Sites);
                true
            }
            ids::SITES_REVOKE_ALL => {
                self.set_screen(crate::app::Screen::Confirm(Confirm::DisconnectAll));
                true
            }
            _ => {
                let Some(offset) = id
                    .checked_sub(ids::SITE_ROW_BASE)
                    .filter(|offset| *offset < ids::SITE_ROW_SPAN)
                else {
                    return false;
                };
                let offset = usize::from(offset);
                let grants = self.browser_grants();
                let (sol, btc) = self.chain_grants();
                if let Some(site) = grants.get(offset) {
                    let origin = site.origin.clone();
                    self.disconnect_site(&origin);
                } else if let Some(grant) = sol.get(offset - grants.len()) {
                    let origin = grant.origin.clone();
                    self.disconnect_chain_site(&origin, yw_core::policy::Family::Solana);
                } else if let Some(grant) = btc.get(offset - grants.len() - sol.len()) {
                    let origin = grant.origin.clone();
                    self.disconnect_chain_site(&origin, yw_core::policy::Family::Bitcoin);
                }
                true
            }
        }
    }
}
