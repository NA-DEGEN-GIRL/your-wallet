//! The E-VLT-006 overlays of a wallet side file that does not open (spec/04 §2.5, spec/02 §6.3):
//! their command ids and render builders, and the journal's bands on the send forms and every
//! screen. 2026-11-22 (S4d E0c): moved from `app_sidecar`, which keeps the choices themselves
//! (wallet code, `Wallet::on_sidecar` and the overlay state `SidecarUi`) and their texts; before,
//! the `ids` module, `local_time` and these `impl App` builders sat there too.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): moved here from yw-app `ui/screens_sidecar.rs` with the
//! bodies unchanged (`impl App` builders became `impl Screen<'_>`, yw-app paths engine paths); its
//! control ids stay there (`ui::screens_sidecar::ids`).

use yw_core::lang::Text;
use yw_core::vault::FileKind;

use crate::cmd::{CorePress, SidecarPress};
use crate::errors::ErrorCode;
use crate::screen::Tone;
use crate::screen::model::{Ctl, Item};
use crate::wallet::app_sidecar::{JournalHold, RESET_WATCH_SECS, SendChain, text};
use crate::wallet::{AppMode, Confirm, Screen};

/// `YYYY-MM-DD HH:MM` in local time (spec/04 §2.6); UTC with a suffix if the conversion fails.
fn local_time(facts: &dyn crate::screen::facts::ScreenFacts, unix_secs: u64) -> String {
    let unix_ms = unix_secs.saturating_mul(1_000);
    let wall = facts.local_wall_ms(unix_ms);
    let text = crate::logging::format_utc(wall.unwrap_or(unix_ms));
    let short = text.get(..16).unwrap_or(&text).replace('T', " ");
    if wall.is_some() {
        short
    } else {
        format!("{short} UTC")
    }
}

impl super::Screen<'_> {
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
                        text::BTC_RESET.fill(lang, [&local_time(&self.facts(), at)]),
                        Tone::HighRisk,
                    ));
                    items.push(Item::Row(vec![Ctl::check(
                        SidecarPress::ResetAck(None),
                        text::BTC_RESET_ACK.get(lang),
                        self.sidecar.reset_ack,
                    )]));
                }
                return;
            }
        };
        if let Some(JournalHold::Wait(until)) = self.journal_hold(chain) {
            items.push(Item::Banner(
                text::RESET_WAIT.fill(lang, [name, &local_time(&self.facts(), until)]),
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
            SidecarPress::JournalReopen,
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
            SidecarPress::Advanced,
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
                Ctl::primary(SidecarPress::Close, text::CLOSE_UNCHANGED.get(lang)),
                Ctl::button(CorePress::Lock, text::LOCK.get(lang)),
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
                Ctl::button(CorePress::SidecarPrev, text::USE_PREV.get(lang))
            } else {
                Ctl::primary(CorePress::SidecarPrev, text::USE_PREV.get(lang))
            });
        }
        row.push(Ctl::danger(
            CorePress::SidecarFresh,
            text::QUARANTINE.get(lang),
        ));
        if !newer {
            items.push(Item::Help(t(text::META_CLOSE)));
            row.push(Ctl::button(
                SidecarPress::Close,
                text::CLOSE_UNCHANGED.get(lang),
            ));
        }
        items.push(Item::Row(row));
        items.push(Item::CardEnd);
    }

    /// The journal overlay (`Confirm::JournalCorrupt`).
    pub(crate) fn journal_overlay(&self, items: &mut Vec<Item>) {
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
                Ctl::primary(CorePress::ConfirmNo, text::CLOSE_SENDS_STOP.get(lang)),
                Ctl::button(CorePress::Lock, text::LOCK.get(lang)),
            ]));
            self.advanced_link(items);
            if self.sidecar.advanced {
                items.push(Item::Banner(t(text::NEWER_ADVANCED), Tone::HighRisk));
                items.push(Item::Banner(t(text::JOURNAL_RESET), Tone::HighRisk));
                items.push(Item::Row(vec![Ctl::danger(
                    CorePress::ConfirmYes,
                    text::QUARANTINE.get(lang),
                )]));
            }
        } else {
            items.push(Item::Banner(t(text::JOURNAL_RESET), Tone::HighRisk));
            items.push(Item::Row(vec![
                Ctl::danger(CorePress::ConfirmYes, text::QUARANTINE.get(lang)),
                Ctl::button(CorePress::ConfirmNo, text::CLOSE_SENDS_STOP.get(lang)),
            ]));
        }
        items.push(Item::CardEnd);
    }
}
