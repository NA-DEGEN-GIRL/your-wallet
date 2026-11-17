//! Presses of S23 `Chrome 확장 설치` and its entry links (`ui::screens_reset` on Windows;
//! spec/04 §2.21).
//!
//! 2026-11-18 (S3 C5): created.

/// A press of S23.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtPress {
    /// `Chrome 확장 설치` (settings, S08, S13).
    Open,
    /// S23 `← 돌아가기`.
    Back,
    /// S23 `탐색기에서 폴더 열기`.
    OpenFolder,
    /// S23 `확장 폴더 경로 복사`.
    CopyPath,
    /// S23 `chrome://extensions 주소 복사`.
    CopyUrl,
}
