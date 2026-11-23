//! S13 연결된 사이트 (spec/04 §2.9): every grant with its origin (http badge), accounts in return
//! order, origin chain and connection time; `연결 해제` per row and `모두 해제` (confirmation).
//! The three families' cards have one order (2026-11-12): network, connection time, `연결 해제`,
//! then the accounts with grouped addresses.
//! Solana and Bitcoin connections (spec/05 §4.9: ownership proof only) follow the EVM grants with
//! their own `연결 해제` rows. The combined list (up to 3 × 256 grants) is shown
//! [`ids::SITES_PAGE_ROWS`] cards per page; each button disconnects the `(origin, family)` it was
//! drawn for ([`crate::wallet::app_browser::SiteRows`]), never "the n-th row of the list now".
//! Also the S07 T-UNLOCK-PENDING line (spec/04 §2.5, §2.16).
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): moved here from yw-app `ui/screens_sites.rs` with the
//! bodies unchanged (`impl App` builders became `impl Screen<'_>`, yw-app paths engine paths); its
//! control ids stay there (`ui::screens_sites::ids`).

use yw_core::lang::Lang;
use yw_core::policy::{BrowserOrigin, Family};

use super::Screen;
use crate::cmd::{Row, SitesPress};
use crate::meta::BookChain;
use crate::screen::Tone;
use crate::screen::build::book::shown_address;
use crate::screen::model::{Ctl, Item};
use crate::wallet::app_browser::SITES_PAGE_ROWS;

/// The page being drawn: which cards of the combined list it shows, and the grant behind each
/// row button (recorded for [`Wallet::on_sites`]).
struct Page<'a> {
    start: usize,
    end: usize,
    keys: Option<core::cell::RefMut<'a, Vec<(BrowserOrigin, Family)>>>,
    lang: Lang,
}

impl Page<'_> {
    fn shows(&self, index: usize) -> bool {
        (self.start..self.end).contains(&index)
    }

    /// The `연결 해제` row of a card, right under its connection time (none when the id range or
    /// the record is unavailable).
    fn button(&mut self, origin: &BrowserOrigin, family: Family) -> Option<Item> {
        let keys = self.keys.as_mut()?;
        let press = u16::try_from(keys.len())
            .ok()
            .filter(|offset| usize::from(*offset) < SITES_PAGE_ROWS)
            .map(|offset| SitesPress::Disconnect(Row(offset)))?;
        keys.push((origin.clone(), family));
        Some(Item::Row(vec![
            Ctl::danger(press, text::DISCONNECT.get(self.lang)).compact(),
        ]))
    }
}

/// The page line and `이전 쪽`/`다음 쪽` (only with more than one page).
fn page_nav(lang: Lang, items: &mut Vec<Item>, total: usize, pages: usize, shown: usize) {
    if pages <= 1 {
        return;
    }
    items.push(Item::Text(text::PAGE_LINE.fill(
        lang,
        [
            &(shown + 1).to_string(),
            &pages.to_string(),
            &total.to_string(),
            &SITES_PAGE_ROWS.to_string(),
        ],
    )));
    let mut nav = Vec::new();
    if shown > 0 {
        nav.push(Ctl::button(SitesPress::Prev, text::PREV_PAGE.get(lang)));
    }
    if shown + 1 < pages {
        nav.push(Ctl::button(SitesPress::Next, text::NEXT_PAGE.get(lang)));
    }
    items.push(Item::Row(nav));
}

fn local_time(facts: &dyn crate::screen::facts::ScreenFacts, unix_ms: u64) -> String {
    let local = facts.local_wall_ms(unix_ms);
    let text = crate::logging::format_utc(local.unwrap_or(unix_ms));
    let short = text.get(..16).unwrap_or(&text).replace('T', " ");
    if local.is_some() {
        short
    } else {
        format!("{short} UTC")
    }
}

/// S13 texts and T-UNLOCK-PENDING (spec/04 §2.5, §2.9; English spec/14 §5).
pub mod text {
    yw_core::texts! {
        DISCONNECT = "연결 해제" / "Disconnect";
        /// `{0}` page, `{1}` pages, `{2}` connections, `{3}` cards per page.
        PAGE_LINE(4) = "{0} / {1}쪽 (연결 {2}곳, 한 쪽에 {3}곳)"
            / "Page {0} / {1} ({2} connections, {3} per page)";
        PREV_PAGE = "이전 쪽" / "Previous page";
        NEXT_PAGE = "다음 쪽" / "Next page";
        /// What a Bitcoin connection allows (spec/05 §4.9), on its own line of the card.
        PROOF_ONLY = "메시지 서명·소유 증명만" / "Message signing and proof of ownership only";
        /// What a Solana connection allows (spec/04 §2.9, 2026-11-12: dApp transactions, D38).
        SOL_RIGHTS = "연결·메시지 서명·거래 서명(매번 승인)"
            / "Connect, message signing, transaction signing (approved each time)";
        SITE_DEFAULT = "사이트가 기본으로 쓰는 계정" / "Account the site uses by default";
        SITE_DEFAULT_LABEL(1) = "{0} · 사이트가 기본으로 쓰는 계정"
            / "{0} · account the site uses by default";
        /// One family of the count line (`{0}` family, `{1}` count).
        SUMMARY_PART(2) = "{0} {1}곳" / "{0} {1}";
        SUMMARY(1) = "연결 {0}" / "Connected: {0}";
        TITLE = "연결된 사이트 · WalletConnect" / "Connected sites · WalletConnect";
        HELP = "연결된 사이트는 아래 계정의 주소를 볼 수 있고, EVM 사이트는 잔액과 거래 기록도 읽을 수 있습니다. 서명과 전송은 매번 이 앱의 확인 창에서 따로 승인합니다."
            / "Connected sites can see the addresses of the accounts below, and EVM sites can also read balances and transaction history. Every signature and transfer is approved separately in this app's confirmation window.";
        NONE = "연결된 사이트가 없습니다" / "No connected sites";
        NONE_HELP = "dApp 사이트에서 '지갑 연결'을 누르고 이 앱의 연결 창에서 승인하면 여기에 표시됩니다."
            / "Press 'Connect wallet' on a dApp site and approve it in this app's connect window; the site then appears here.";
        LOCAL_HTTP = "로컬 개발 사이트(http)" / "Local development site (http)";
        NETWORK = "네트워크" / "Network";
        CONNECTED_AT = "연결 시각" / "Connected at";
        RIGHTS = "권한" / "Permissions";
        DISCONNECT_ALL = "모든 사이트 연결 해제" / "Disconnect all sites";
        PENDING_MORE(1) = " 외 {0}건" / " and {0} more";
        /// T-UNLOCK-PENDING (`{0}` count, `{1}` origins).
        PENDING(2) = "잠금 해제를 기다리는 요청 {0}건: {1}" / "Requests waiting for unlock ({0}): {1}";
    }
}

/// The label line of an EVM card's account; the grant's first account is the one the site uses
/// (U9's line of the connect window, 2026-11-10) and says so when the site sees several.
fn account_label(lang: Lang, label: &str, site_default: bool) -> String {
    match (site_default, label.is_empty()) {
        (false, _) => label.to_owned(),
        (true, true) => text::SITE_DEFAULT.get(lang).to_owned(),
        (true, false) => text::SITE_DEFAULT_LABEL.fill(lang, [label]),
    }
}

/// The count line above the cards ("EVM 2곳 · Solana 1곳").
fn sites_summary(lang: Lang, evm: usize, sol: usize, btc: usize) -> String {
    let parts: Vec<String> = [("EVM", evm), ("Solana", sol), ("Bitcoin", btc)]
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .map(|(family, count)| text::SUMMARY_PART.fill(lang, [family, &count.to_string()]))
        .collect();
    text::SUMMARY.fill(lang, [&parts.join(" · ")])
}

impl Screen<'_> {
    /// The S13 page to draw for `total` cards (its button record cleared), the page count, the
    /// page index and `total`.
    fn sites_page(&self, total: usize) -> (Page<'_>, usize, usize, usize) {
        let browser = self.browser.as_ref();
        let (pages, shown) = crate::wallet::app_browser::page_of(
            total,
            browser.map_or(0, |browser| browser.site_rows.page),
        );
        let page = Page {
            start: shown * SITES_PAGE_ROWS,
            end: (shown + 1) * SITES_PAGE_ROWS,
            keys: browser.map(|browser| {
                let mut keys = browser.site_rows.keys.borrow_mut();
                keys.clear();
                keys
            }),
            lang: self.settings.language,
        };
        (page, pages, shown, total)
    }

    /// S13.
    pub(crate) fn sites_screen(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(self.back_row());
        items.push(Item::Title(text::TITLE.get(lang).to_owned()));
        // WalletConnect sessions have their own cards (spec/13 §6).
        self.wc_panel(items);
        let grants: Vec<_> = self
            .browser_grants()
            .into_iter()
            .filter(|grant| !crate::walletconnect::is_session_origin(&grant.origin))
            .collect();
        let (sol_grants, btc_grants) = self.chain_grants();
        items.push(Item::Help(text::HELP.get(lang).to_owned()));
        if !(grants.is_empty() && sol_grants.is_empty() && btc_grants.is_empty()) {
            items.push(Item::Text(sites_summary(
                lang,
                grants.len(),
                sol_grants.len(),
                btc_grants.len(),
            )));
        }
        if grants.is_empty() && sol_grants.is_empty() && btc_grants.is_empty() {
            items.push(Item::CardStart(None));
            items.push(Item::Subtitle(text::NONE.get(lang).to_owned()));
            items.push(Item::Text(text::NONE_HELP.get(lang).to_owned()));
            items.push(Item::Help(
                crate::screen::build::reset::T_EXT_COMPAT_SHORT
                    .get(self.settings.language)
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
            items.push(Item::CardStart(Some(
                crate::wallet::app_browser::card_title(&site.origin, Family::Evm),
            )));
            if site.origin.is_http() {
                items.push(Item::Banner(
                    text::LOCAL_HTTP.get(lang).to_owned(),
                    Tone::Warn,
                ));
            }
            let chain = self
                .settings
                .evm_chain_name_in(lang, site.chain_id)
                .unwrap_or_else(|| format!("chainId {}", site.chain_id));
            items.push(Item::Badged(
                crate::badge::Badge::evm(site.chain_id, &chain),
                Box::new(Item::Field(text::NETWORK.get(lang).to_owned(), chain)),
            ));
            items.push(Item::Field(
                text::CONNECTED_AT.get(lang).to_owned(),
                local_time(&self.facts(), site.granted_at_unix_ms),
            ));
            items.extend(page.button(&site.origin, Family::Evm));
            for (index, account) in site.accounts.iter().enumerate() {
                let label = labels
                    .iter()
                    .find(|(address, _)| address == account)
                    .map_or("", |(_, label)| label.as_str());
                items.push(Item::Help(account_label(
                    lang,
                    label,
                    index == 0 && site.accounts.len() > 1,
                )));
                items.push(Item::Mono(yw_core::evm::display::format_address(account)));
            }
            items.push(Item::CardEnd);
        }
        self.chain_site_cards(&mut page, grants.len(), &sol_grants, &btc_grants, items);
        drop(page);
        page_nav(lang, items, total, pages, shown);
        items.push(Item::Row(vec![Ctl::danger(
            SitesPress::RevokeAll,
            text::DISCONNECT_ALL.get(lang),
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
        let lang = self.settings.language;
        let sol_labels = self.sol_dapp_rows();
        for (offset, grant) in sol_grants.iter().enumerate() {
            if !page.shows(first + offset) {
                continue;
            }
            items.push(Item::CardStart(Some(
                crate::wallet::app_browser::card_title(&grant.origin, Family::Solana),
            )));
            items.push(Item::Badged(
                crate::badge::Badge::family(BookChain::Sol),
                Box::new(Item::Field(
                    text::NETWORK.get(lang).to_owned(),
                    "Solana".to_owned(),
                )),
            ));
            items.push(Item::Field(
                text::RIGHTS.get(lang).to_owned(),
                text::SOL_RIGHTS.get(lang).to_owned(),
            ));
            items.push(Item::Field(
                text::CONNECTED_AT.get(lang).to_owned(),
                local_time(&self.facts(), grant.granted_at_unix_ms),
            ));
            items.extend(page.button(&grant.origin, Family::Solana));
            items.push(Item::Help(
                sol_labels
                    .iter()
                    .find(|row| row.public == grant.public)
                    .map_or_else(String::new, |row| row.label.clone()),
            ));
            items.push(Item::Mono(shown_address(
                BookChain::Sol,
                &yw_core::codec::base58::base58_encode(&grant.public),
            )));
            items.push(Item::CardEnd);
        }
        for (offset, grant) in btc_grants.iter().enumerate() {
            if !page.shows(first + sol_grants.len() + offset) {
                continue;
            }
            items.push(Item::CardStart(Some(
                crate::wallet::app_browser::card_title(&grant.origin, Family::Bitcoin),
            )));
            items.push(Item::Badged(
                crate::badge::Badge::bitcoin(grant.network),
                Box::new(Item::Field(
                    text::NETWORK.get(lang).to_owned(),
                    yw_core::btc::text::network_name(lang, grant.network).to_owned(),
                )),
            ));
            items.push(Item::Field(
                text::RIGHTS.get(lang).to_owned(),
                text::PROOF_ONLY.get(lang).to_owned(),
            ));
            items.push(Item::Field(
                text::CONNECTED_AT.get(lang).to_owned(),
                local_time(&self.facts(), grant.granted_at_unix_ms),
            ));
            items.extend(page.button(&grant.origin, Family::Bitcoin));
            for entry in &grant.addresses {
                items.push(Item::Help(entry.purpose.label_in(lang).to_owned()));
                items.push(Item::Mono(shown_address(BookChain::Btc, &entry.address)));
            }
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
            .filter(|item| matches!(item, crate::wallet::app_evm::QueuedItem::Site(_)))
            .count();
        let shown: Vec<&str> = origins.iter().take(5).map(String::as_str).collect();
        let lang = self.settings.language;
        let mut list = shown.join(", ");
        if origins.len() > 5 {
            list.push_str(&text::PENDING_MORE.fill(lang, [&(origins.len() - 5).to_string()]));
        }
        Some(text::PENDING.fill(lang, [&count.to_string(), &list]))
    }
}
