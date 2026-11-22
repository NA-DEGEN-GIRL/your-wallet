//! The E-VLT-006 overlays of a wallet side file that does not open (spec/04 §2.5, spec/02 §6.3):
//! their command ids and render builders, and the journal's bands on the send forms and every
//! screen. 2026-11-22 (S4d E0c): moved from `app_sidecar`, which keeps the choices themselves
//! (wallet code, `Wallet::on_sidecar` and the overlay state `SidecarUi`) and their texts; before,
//! the `ids` module, `local_time` and these `impl App` builders sat there too.

use yw_core::lang::Text;
use yw_core::vault::FileKind;

use crate::app::{App, AppMode, Confirm, Screen};
use crate::app_sidecar::{JournalHold, RESET_WATCH_SECS, SendChain, text};
use crate::errors::ErrorCode;
use crate::ui::main_window::{Ctl, Item};
use yw_engine::screen::Tone;

/// Command ids (block 16,600–16,609 of `ui::command_ids`). The overlays' other buttons keep their
/// ids: meta `SIDECAR_PREV`/`SIDECAR_FRESH`, journal `CONFIRM_YES`/`CONFIRM_NO`, `LOCK`.
pub mod ids {
    /// The meta overlay's `닫기 (아무것도 바꾸지 않음)`.
    pub const SIDECAR_CLOSE: u16 = 16_600;
    /// `고급` of a newer-format overlay (the destructive choices).
    pub const ADVANCED: u16 = 16_601;
    /// `선택 다시 보기` of the closed journal's band.
    pub const JOURNAL_REOPEN: u16 = 16_602;
    /// The Bitcoin send form's check after a journal reset.
    pub const RESET_ACK: u16 = 16_603;
    /// Every fixed id.
    pub const FIXED: &[u16] = &[SIDECAR_CLOSE, ADVANCED, JOURNAL_REOPEN, RESET_ACK];

    /// The press control `id` stands for (2026-11-18, S3 C1: `ui::cmd_table`); the reset check
    /// carries its box's state now. `None` when `id` is not one of this module's.
    #[must_use]
    pub fn press_of(
        id: u16,
        controls: &crate::ui::main_window::ControlSet,
    ) -> Option<yw_engine::cmd::SidecarPress> {
        use yw_engine::cmd::SidecarPress;
        Some(match id {
            SIDECAR_CLOSE => SidecarPress::Close,
            ADVANCED => SidecarPress::Advanced,
            JOURNAL_REOPEN => SidecarPress::JournalReopen,
            RESET_ACK => SidecarPress::ResetAck(controls.checked(id)),
            _ => return None,
        })
    }

    /// The control id of `press` (the inverse of [`press_of`]).
    #[must_use]
    pub const fn id_of(press: yw_engine::cmd::SidecarPress) -> u16 {
        use yw_engine::cmd::SidecarPress;
        match press {
            SidecarPress::Close => SIDECAR_CLOSE,
            SidecarPress::Advanced => ADVANCED,
            SidecarPress::JournalReopen => JOURNAL_REOPEN,
            SidecarPress::ResetAck(_) => RESET_ACK,
        }
    }
}

/// `YYYY-MM-DD HH:MM` in local time (spec/04 §2.6); UTC with a suffix if the conversion fails.
fn local_time(unix_secs: u64) -> String {
    let unix_ms = unix_secs.saturating_mul(1_000);
    let wall = yw_win::time::local_wall_ms(unix_ms);
    let text = crate::logging::format_utc(wall.unwrap_or(unix_ms));
    let short = text.get(..16).unwrap_or(&text).replace('T', " ");
    if wall.is_some() {
        short
    } else {
        format!("{short} UTC")
    }
}

impl App {
    /// Above a send form's `검토`: why the journal holds it — closed (one line; the header band
    /// has the reason and `선택 다시 보기`), or the wait or the check after a journal reset.
    pub(crate) fn journal_send_items(&self, chain: SendChain, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        if self.sidecar.journal_closed {
            items.push(Item::Help(text::SEND_STOPPED.get(lang).to_owned()));
            return;
        }
        let name = match chain {
            SendChain::Evm => return,
            SendChain::Sol => "Solana",
            SendChain::Zec => "Zcash",
            SendChain::Btc => {
                if let Some((at, _)) =
                    self.reset_elapsed(RESET_WATCH_SECS, self.clock.now_unix_ms() / 1_000)
                {
                    items.push(Item::Banner(
                        text::BTC_RESET.fill(lang, [&local_time(at)]),
                        Tone::HighRisk,
                    ));
                    items.push(Item::Row(vec![Ctl::check(
                        ids::RESET_ACK,
                        text::BTC_RESET_ACK.get(lang),
                        self.sidecar.reset_ack,
                    )]));
                }
                return;
            }
        };
        if let Some(JournalHold::Wait(until)) = self.journal_hold(chain) {
            items.push(Item::Banner(
                text::RESET_WAIT.fill(lang, [name, &local_time(until)]),
                Tone::Warn,
            ));
        }
    }

    /// The closed journal's band with `선택 다시 보기`, on every screen of the session.
    pub(crate) fn journal_closed_items(&self, items: &mut Vec<Item>) {
        if !self.sidecar.journal_closed
            || !matches!(self.mode, AppMode::Unlocked { .. })
            || self.screen == Screen::Confirm(Confirm::JournalCorrupt)
        {
            return;
        }
        let lang = self.settings.language;
        items.push(Item::Banner(
            format!(
                "{} ({})",
                text::JOURNAL_CLOSED.get(lang),
                ErrorCode::Vlt006.code()
            ),
            Tone::Blocked,
        ));
        items.push(Item::Row(vec![Ctl::button(
            ids::JOURNAL_REOPEN,
            text::SHOW_CHOICES.get(lang),
        )]));
    }

    fn refusal_items(&self, items: &mut Vec<Item>) {
        if let Some(text) = &self.sidecar.refusal {
            items.push(Item::Banner(text.clone(), Tone::Danger));
        }
    }

    fn advanced_link(&self, items: &mut Vec<Item>) {
        items.push(Item::Row(vec![Ctl::link(
            ids::ADVANCED,
            if self.sidecar.advanced {
                text::ADVANCED_HIDE
            } else {
                text::ADVANCED_SHOW
            }
            .get(self.settings.language),
        )]));
    }

    /// The meta overlay (`Confirm::SidecarCorrupt`).
    pub(crate) fn meta_overlay(&self, items: &mut Vec<Item>) {
        use crate::ui::screens::ids as core;
        let prev = self.store.prev_exists(FileKind::Meta);
        let newer = self.sidecar.meta_newer;
        let lang = self.settings.language;
        let t = |entry: Text| entry.get(lang).to_owned();
        items.push(Item::Title(t(if newer {
            text::META_NEWER_TITLE
        } else {
            text::META_DAMAGED_TITLE
        })));
        items.push(Item::CardStart(None));
        items.push(Item::Text(t(if newer {
            text::META_NEWER
        } else {
            text::META_DAMAGED
        })));
        self.refusal_items(items);
        if newer {
            items.push(Item::Row(vec![
                Ctl::primary(ids::SIDECAR_CLOSE, text::CLOSE_UNCHANGED.get(lang)),
                Ctl::button(core::LOCK, text::LOCK.get(lang)),
            ]));
            self.advanced_link(items);
            if !self.sidecar.advanced {
                items.push(Item::CardEnd);
                return;
            }
            items.push(Item::Banner(t(text::NEWER_ADVANCED), Tone::HighRisk));
        }
        if prev {
            items.push(Item::Help(t(text::META_PREV)));
        }
        items.push(Item::Help(t(text::META_FRESH)));
        let mut row = Vec::new();
        if prev {
            row.push(if newer {
                Ctl::button(core::SIDECAR_PREV, text::USE_PREV.get(lang))
            } else {
                Ctl::primary(core::SIDECAR_PREV, text::USE_PREV.get(lang))
            });
        }
        row.push(Ctl::danger(core::SIDECAR_FRESH, text::QUARANTINE.get(lang)));
        if !newer {
            items.push(Item::Help(t(text::META_CLOSE)));
            row.push(Ctl::button(
                ids::SIDECAR_CLOSE,
                text::CLOSE_UNCHANGED.get(lang),
            ));
        }
        items.push(Item::Row(row));
        items.push(Item::CardEnd);
    }

    /// The journal overlay (`Confirm::JournalCorrupt`).
    pub(crate) fn journal_overlay(&self, items: &mut Vec<Item>) {
        use crate::ui::screens::ids as core;
        let newer = self.sidecar.journal_newer;
        let lang = self.settings.language;
        let t = |entry: Text| entry.get(lang).to_owned();
        items.push(Item::Title(t(if newer {
            text::JOURNAL_NEWER_TITLE
        } else {
            text::JOURNAL_DAMAGED_TITLE
        })));
        items.push(Item::CardStart(None));
        items.push(Item::Text(t(if newer {
            text::JOURNAL_NEWER
        } else {
            text::JOURNAL_DAMAGED
        })));
        self.refusal_items(items);
        if newer {
            items.push(Item::Row(vec![
                Ctl::primary(core::CONFIRM_NO, text::CLOSE_SENDS_STOP.get(lang)),
                Ctl::button(core::LOCK, text::LOCK.get(lang)),
            ]));
            self.advanced_link(items);
            if self.sidecar.advanced {
                items.push(Item::Banner(t(text::NEWER_ADVANCED), Tone::HighRisk));
                items.push(Item::Banner(t(text::JOURNAL_RESET), Tone::HighRisk));
                items.push(Item::Row(vec![Ctl::danger(
                    core::CONFIRM_YES,
                    text::QUARANTINE.get(lang),
                )]));
            }
        } else {
            items.push(Item::Banner(t(text::JOURNAL_RESET), Tone::HighRisk));
            items.push(Item::Row(vec![
                Ctl::danger(core::CONFIRM_YES, text::QUARANTINE.get(lang)),
                Ctl::button(core::CONFIRM_NO, text::CLOSE_SENDS_STOP.get(lang)),
            ]));
        }
        items.push(Item::CardEnd);
    }
}
