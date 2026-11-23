//! S13 연결된 사이트 (spec/04 §2.9): every grant with its origin (http badge), accounts in return
//! order, origin chain and connection time; `연결 해제` per row and `모두 해제` (confirmation).
//! The three families' cards have one order (2026-11-12): network, connection time, `연결 해제`,
//! then the accounts with grouped addresses.
//! Solana and Bitcoin connections (spec/05 §4.9: ownership proof only) follow the EVM grants with
//! their own `연결 해제` rows. The combined list (up to 3 × 256 grants) is shown
//! [`ids::SITES_PAGE_ROWS`] cards per page; each button disconnects the `(origin, family)` it was
//! drawn for ([`yw_engine::wallet::app_browser::SiteRows`]), never "the n-th row of the list now".
//! Also the S07 T-UNLOCK-PENDING line (spec/04 §2.5, §2.16).
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): the builders, their helpers and texts moved to yw-engine
//! `screen::build::sites` (bodies unchanged); this file keeps the control ids of its controls
//! (`ids`) and the tests' press adapter, which only the Windows shell has.

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
    /// Cards per page. 2026-11-23 (S4d E0b): the wallet's `app_browser::SITES_PAGE_ROWS` (the S13
    /// handler pages with it), re-used here; before, defined here.
    pub const SITES_PAGE_ROWS: usize = yw_engine::wallet::app_browser::SITES_PAGE_ROWS;
    /// Every fixed id of this module.
    pub const FIXED: &[u16] = &[SITES_OPEN, SITES_REVOKE_ALL, SITES_PREV, SITES_NEXT];

    /// The press control `id` stands for (2026-11-18, S3 C2: `ui::cmd_table`); `None` when `id`
    /// is not one of this module's.
    #[must_use]
    pub fn press_of(id: u16) -> Option<yw_engine::cmd::SitesPress> {
        use yw_engine::cmd::{Row, SitesPress};
        Some(match id {
            SITES_OPEN => SitesPress::Open,
            SITES_REVOKE_ALL => SitesPress::RevokeAll,
            SITES_PREV => SitesPress::Prev,
            SITES_NEXT => SitesPress::Next,
            _ => SitesPress::Disconnect(Row(id
                .checked_sub(SITE_ROW_BASE)
                .filter(|offset| *offset < SITE_ROW_SPAN)?)),
        })
    }

    /// The control id of `press` (the inverse of [`press_of`]).
    #[must_use]
    pub const fn id_of(press: yw_engine::cmd::SitesPress) -> u16 {
        use yw_engine::cmd::{Row, SitesPress};
        match press {
            SitesPress::Open => SITES_OPEN,
            SitesPress::RevokeAll => SITES_REVOKE_ALL,
            SitesPress::Prev => SITES_PREV,
            SitesPress::Next => SITES_NEXT,
            SitesPress::Disconnect(Row(row)) => SITE_ROW_BASE.wrapping_add(row),
        }
    }
}

#[cfg(test)]
impl crate::app::App {
    /// Test adapter (S3 C2, plan §3.2): presses S13 control `id` directly, as the tests did
    /// before; `false` when `id` is not one.
    pub(crate) fn on_sites_command(&mut self, id: u16) -> bool {
        self.press_family(
            id,
            |press| match press {
                yw_engine::cmd::Press::Sites(press) => Some(press),
                _ => None,
            },
            |app, press| {
                crate::app::test_steps::on_sites(&mut app.wallet, press);
                true
            },
        )
    }
}
