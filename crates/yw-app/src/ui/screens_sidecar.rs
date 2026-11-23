//! The E-VLT-006 overlays of a wallet side file that does not open (spec/04 §2.5, spec/02 §6.3):
//! their command ids and render builders, and the journal's bands on the send forms and every
//! screen. 2026-11-22 (S4d E0c): moved from `app_sidecar`, which keeps the choices themselves
//! (wallet code, `Wallet::on_sidecar` and the overlay state `SidecarUi`) and their texts; before,
//! the `ids` module, `local_time` and these `impl App` builders sat there too.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): the builders, their helpers and texts moved to yw-engine
//! `screen::build::sidecar` (bodies unchanged); this file keeps the control ids of its controls
//! (`ids`), which only the Windows shell has.

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
