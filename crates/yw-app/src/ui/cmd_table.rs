//! The main window's control id ↔ [`Press`] table (spec/04 §2.1, spec/15 §11.4 S3). The window
//! reports a click as a control id (`WM_COMMAND`); `App::on_command` turns it into a
//! `Cmd::Press` with [`press_of`], and [`id_of`] gives the id back where the Windows shell still
//! keys state by id (the copy mark `App::command`, an open drop-down).
//!
//! 2026-11-18 (S3 B2): created. Enter and Esc map to `Press::Enter`/`Press::Back`; every other id
//! is `Press::Legacy(id)` until its handler family is converted (S3 C1–C12), and `Legacy` goes in
//! S3 D3.

use yw_engine::cmd::Press;

/// The command id `IsDialogMessageW` sends for Enter (no control uses it, `ui::command_ids`).
pub const IDOK: u16 = 1;
/// The one it sends for Esc.
pub const IDCANCEL: u16 = 2;

/// The press a control id stands for.
#[must_use]
pub const fn press_of(id: u16) -> Press {
    match id {
        IDOK => Press::Enter,
        IDCANCEL => Press::Back,
        other => Press::Legacy(other),
    }
}

/// The control id of a press (the inverse of [`press_of`]).
#[must_use]
pub const fn id_of(press: Press) -> u16 {
    match press {
        Press::Enter => IDOK,
        Press::Back => IDCANCEL,
        Press::Legacy(id) => id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::command_ids::{fixed, ranges};
    use crate::ui::screens_reset;

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
        for id in ids {
            assert!(id != IDOK && id != IDCANCEL, "{id} is Enter or Esc");
            assert_eq!(id_of(press_of(id)), id, "{id}");
        }
        assert_eq!(press_of(IDOK), Press::Enter);
        assert_eq!(press_of(IDCANCEL), Press::Back);
        assert_eq!(id_of(Press::Enter), IDOK);
        assert_eq!(id_of(Press::Back), IDCANCEL);
    }

    /// Table test (6): S22's 2 s hold area is painted, not a control; it never becomes a family
    /// press that a click could post.
    #[test]
    fn reset_hold_stays_unpressable() {
        let hold = screens_reset::ids::RESET_HOLD;
        assert_eq!(press_of(hold), Press::Legacy(hold));
    }
}
