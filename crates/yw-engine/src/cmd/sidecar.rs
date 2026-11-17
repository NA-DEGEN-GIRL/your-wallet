//! Presses of the side-file overlays, the closed journal's band and the Bitcoin send form's
//! check after a journal reset (`app_sidecar` on Windows; spec/04 §2.5).
//!
//! 2026-11-18 (S3 C1): created.

/// A side-file press.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SidecarPress {
    /// The meta overlay's `닫기 (아무것도 바꾸지 않음)`.
    Close,
    /// `고급` of a newer-format overlay.
    Advanced,
    /// `선택 다시 보기` of the closed journal's band.
    JournalReopen,
    /// The Bitcoin send form's check after a journal reset: the box's state when it was pressed
    /// (`None`: no such box).
    ResetAck(Option<bool>),
}
