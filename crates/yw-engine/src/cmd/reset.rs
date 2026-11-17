//! Presses of S22 `지갑 초기화` and of T-WAIT-STALLED (`ui::screens_reset` on Windows; spec/04
//! §2.20). The 2 s hold area of S22 is not a press: it is a mouse hold the shell times.
//!
//! 2026-11-18 (S3 C5): created.

/// A press of S22 or T-WAIT-STALLED.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetPress {
    /// `지갑 초기화…` (every entry link).
    Open,
    /// S22 `설정과 API 키도 함께 옮기기`: the box's state when it was pressed (`None`: no such
    /// box).
    SettingsCheck(Option<bool>),
    /// S22 `취소`.
    Cancel,
    /// T-WAIT-STALLED `다시 불러오기`.
    WaitRetry,
}
