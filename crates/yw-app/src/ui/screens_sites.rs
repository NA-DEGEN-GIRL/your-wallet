//! S13 연결된 사이트 (spec/04 §2.9): every grant with its origin (http badge), accounts in return
//! order, origin chain and connection time; `연결 해제` per row and `모두 해제` (confirmation).
//! Solana and Bitcoin connections (spec/05 §4.9: ownership proof only) follow the EVM grants with
//! their own `연결 해제` rows. The combined list (up to 3 × 256 grants) is shown
//! [`ids::SITES_PAGE_ROWS`] cards per page; each button disconnects the `(origin, family)` it was
//! drawn for ([`crate::app_browser::SiteRows`]), never "the n-th row of the list now".
//! Also the S07 T-UNLOCK-PENDING line (spec/04 §2.5, §2.16).

use core::fmt::Write as _;

use yw_core::policy::{BrowserOrigin, Family};

use crate::app::{App, Confirm};
use crate::ui::main_window::{Ctl, Item, Tone};

/// Control ids (6,700–6,965; the whole map is `ui::command_ids`).
pub mod ids {
    /// 연결된 사이트.
    pub const SITES_OPEN: u16 = 6_700;
    /// 모두 해제.
    pub const SITES_REVOKE_ALL: u16 = 6_701;
    /// 이전 쪽.
    pub const SITES_PREV: u16 = 6_702;
    /// 다음 쪽.
    pub const SITES_NEXT: u16 = 6_703;
    /// Row buttons (`연결 해제`), one per card of the page shown.
    pub const SITE_ROW_BASE: u16 = 6_710;
    /// Row span (reserved ids; a page uses [`SITES_PAGE_ROWS`]).
    pub const SITE_ROW_SPAN: u16 = 256;
    /// Cards per page.
    pub const SITES_PAGE_ROWS: usize = 50;
    /// Every fixed id of this module.
    pub const FIXED: &[u16] = &[SITES_OPEN, SITES_REVOKE_ALL, SITES_PREV, SITES_NEXT];
}

/// The page being drawn: which cards of the combined list it shows, and the grant behind each
/// row button (recorded for [`App::on_sites_command`]).
struct Page<'a> {
    start: usize,
    end: usize,
    keys: Option<core::cell::RefMut<'a, Vec<(BrowserOrigin, Family)>>>,
}

impl Page<'_> {
    fn shows(&self, index: usize) -> bool {
        (self.start..self.end).contains(&index)
    }

    /// The `연결 해제` row of a card (none when the id range or the record is unavailable).
    fn button(&mut self, origin: &BrowserOrigin, family: Family) -> Option<Item> {
        let keys = self.keys.as_mut()?;
        let id = u16::try_from(keys.len())
            .ok()
            .filter(|offset| usize::from(*offset) < ids::SITES_PAGE_ROWS)
            .map(|offset| ids::SITE_ROW_BASE + offset)?;
        keys.push((origin.clone(), family));
        Some(Item::Row(vec![Ctl::danger(id, "연결 해제")]))
    }
}

/// Pages of `total` cards and the page shown for the wanted one (clamped to the last page).
fn page_of(total: usize, wanted: usize) -> (usize, usize) {
    let pages = total.div_ceil(ids::SITES_PAGE_ROWS).max(1);
    (pages, wanted.min(pages - 1))
}

/// The page line and `이전 쪽`/`다음 쪽` (only with more than one page).
fn page_nav(items: &mut Vec<Item>, total: usize, pages: usize, shown: usize) {
    if pages <= 1 {
        return;
    }
    items.push(Item::Text(format!(
        "{} / {pages}쪽 (연결 {total}곳, 한 쪽에 {}곳)",
        shown + 1,
        ids::SITES_PAGE_ROWS
    )));
    let mut nav = Vec::new();
    if shown > 0 {
        nav.push(Ctl::button(ids::SITES_PREV, "이전 쪽"));
    }
    if shown + 1 < pages {
        nav.push(Ctl::button(ids::SITES_NEXT, "다음 쪽"));
    }
    items.push(Item::Row(nav));
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

/// A site card title: the full origin, then the chain family (one site may be connected on
/// several chains and gets one card per family).
fn card_title(origin: &yw_core::policy::BrowserOrigin, family: &str) -> String {
    format!("{}  ·  {family}", origin.as_str())
}

/// The count line above the cards ("EVM 2곳 · Solana 1곳").
fn sites_summary(evm: usize, sol: usize, btc: usize) -> String {
    let parts: Vec<String> = [("EVM", evm), ("Solana", sol), ("Bitcoin", btc)]
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .map(|(family, count)| format!("{family} {count}곳"))
        .collect();
    format!("연결 {}", parts.join(" · "))
}

impl App {
    /// The S13 page to draw for `total` cards (its button record cleared), the page count, the
    /// page index and `total`.
    fn sites_page(&self, total: usize) -> (Page<'_>, usize, usize, usize) {
        let browser = self.browser.as_ref();
        let (pages, shown) = page_of(total, browser.map_or(0, |browser| browser.site_rows.page));
        let page = Page {
            start: shown * ids::SITES_PAGE_ROWS,
            end: (shown + 1) * ids::SITES_PAGE_ROWS,
            keys: browser.map(|browser| {
                let mut keys = browser.site_rows.keys.borrow_mut();
                keys.clear();
                keys
            }),
        };
        (page, pages, shown, total)
    }

    /// S13.
    pub(crate) fn sites_screen(&self, items: &mut Vec<Item>) {
        items.push(crate::ui::screens::back_main());
        items.push(Item::Title("연결된 사이트 · WalletConnect".to_owned()));
        // WalletConnect sessions have their own cards (spec/13 §6).
        self.wc_panel(items);
        let grants: Vec<_> = self
            .browser_grants()
            .into_iter()
            .filter(|grant| !crate::walletconnect::is_session_origin(&grant.origin))
            .collect();
        let (sol_grants, btc_grants) = self.chain_grants();
        items.push(Item::Help(
            "연결된 사이트는 아래 계정의 주소를 볼 수 있고, EVM 사이트는 잔액과 거래 기록도 읽을 수 있습니다. 서명과 전송은 매번 이 앱의 확인 창에서 따로 승인합니다."
                .to_owned(),
        ));
        if !(grants.is_empty() && sol_grants.is_empty() && btc_grants.is_empty()) {
            items.push(Item::Text(sites_summary(
                grants.len(),
                sol_grants.len(),
                btc_grants.len(),
            )));
        }
        if grants.is_empty() && sol_grants.is_empty() && btc_grants.is_empty() {
            items.push(Item::CardStart(None));
            items.push(Item::Subtitle("연결된 사이트가 없습니다".to_owned()));
            items.push(Item::Text(
                "dApp 사이트에서 '지갑 연결'을 누르고 이 앱의 연결 창에서 승인하면 여기에 표시됩니다."
                    .to_owned(),
            ));
            self.extension_link(items);
            items.push(Item::CardEnd);
            return;
        }
        let (mut page, pages, shown, total) =
            self.sites_page(grants.len() + sol_grants.len() + btc_grants.len());
        let labels = self.own_accounts();
        for (index, site) in grants.iter().enumerate() {
            if !page.shows(index) {
                continue;
            }
            items.push(Item::CardStart(Some(card_title(&site.origin, "EVM"))));
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
            items.push(Item::Badged(
                crate::ui::badge::Badge::evm(site.chain_id, &chain),
                Box::new(Item::Field("네트워크".to_owned(), chain)),
            ));
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
            items.extend(page.button(&site.origin, Family::Evm));
            items.push(Item::CardEnd);
        }
        self.chain_site_cards(&mut page, grants.len(), &sol_grants, &btc_grants, items);
        drop(page);
        page_nav(items, total, pages, shown);
        items.push(Item::Row(vec![Ctl::danger(
            ids::SITES_REVOKE_ALL,
            "모든 사이트 연결 해제",
        )]));
    }

    /// The Solana and Bitcoin cards of S13 on `page` (their place in the combined list follows
    /// the `first` EVM cards).
    fn chain_site_cards(
        &self,
        page: &mut Page<'_>,
        first: usize,
        sol_grants: &[yw_core::policy::SolGrant],
        btc_grants: &[yw_core::policy::BtcGrant],
        items: &mut Vec<Item>,
    ) {
        let sol_labels = self.sol_dapp_rows();
        for (offset, grant) in sol_grants.iter().enumerate() {
            if !page.shows(first + offset) {
                continue;
            }
            items.push(Item::CardStart(Some(card_title(&grant.origin, "Solana"))));
            items.push(Item::Badged(
                crate::ui::badge::Badge::family(crate::meta::BookChain::Sol),
                Box::new(Item::Field(
                    "네트워크".to_owned(),
                    "Solana (메시지 서명·소유 증명만)".to_owned(),
                )),
            ));
            items.push(Item::Field(
                "연결 시각".to_owned(),
                local_time(grant.granted_at_unix_ms),
            ));
            items.push(Item::Help(
                sol_labels
                    .iter()
                    .find(|row| row.public == grant.public)
                    .map_or_else(String::new, |row| row.label.clone()),
            ));
            items.push(Item::Mono(yw_core::codec::base58::base58_encode(
                &grant.public,
            )));
            items.extend(page.button(&grant.origin, Family::Solana));
            items.push(Item::CardEnd);
        }
        for (offset, grant) in btc_grants.iter().enumerate() {
            if !page.shows(first + sol_grants.len() + offset) {
                continue;
            }
            items.push(Item::CardStart(Some(card_title(&grant.origin, "Bitcoin"))));
            items.push(Item::Badged(
                crate::ui::badge::Badge::bitcoin(grant.network),
                Box::new(Item::Field(
                    "네트워크".to_owned(),
                    format!("{} (메시지 서명·소유 증명만)", grant.network.display_name()),
                )),
            ));
            items.push(Item::Field(
                "연결 시각".to_owned(),
                local_time(grant.granted_at_unix_ms),
            ));
            for entry in &grant.addresses {
                items.push(Item::Help(entry.purpose.label().to_owned()));
                items.push(Item::Mono(entry.address.clone()));
            }
            items.extend(page.button(&grant.origin, Family::Bitcoin));
            items.push(Item::CardEnd);
        }
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
            ids::SITES_PREV | ids::SITES_NEXT => {
                let total = self
                    .browser_grants()
                    .iter()
                    .filter(|grant| !crate::walletconnect::is_session_origin(&grant.origin))
                    .count()
                    + {
                        let (sol, btc) = self.chain_grants();
                        sol.len() + btc.len()
                    };
                if let Some(browser) = self.browser.as_mut() {
                    let (pages, shown) = page_of(total, browser.site_rows.page);
                    browser.site_rows.page = if id == ids::SITES_PREV {
                        shown.saturating_sub(1)
                    } else {
                        (shown + 1).min(pages - 1)
                    };
                }
                self.refresh();
                true
            }
            _ => {
                let Some(offset) = id
                    .checked_sub(ids::SITE_ROW_BASE)
                    .filter(|offset| *offset < ids::SITE_ROW_SPAN)
                else {
                    return false;
                };
                // The grant this button was drawn for (a list that changed since does not move
                // the click to another site).
                let key = self.browser.as_ref().and_then(|browser| {
                    browser
                        .site_rows
                        .keys
                        .borrow()
                        .get(usize::from(offset))
                        .cloned()
                });
                match key {
                    Some((origin, Family::Evm)) => self.disconnect_site(&origin),
                    Some((origin, family)) => self.disconnect_chain_site(&origin, family),
                    None => {}
                }
                true
            }
        }
    }
}
