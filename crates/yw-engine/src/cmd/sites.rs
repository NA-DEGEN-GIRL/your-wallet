//! Presses of S13 `연결된 사이트` (`ui::screens_sites` on Windows; spec/04 §2.9).
//!
//! 2026-11-18 (S3 C2): created.

use crate::cmd::Row;

/// A press on S13.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SitesPress {
    /// `연결된 사이트`: opens S13.
    Open,
    /// `모두 해제` (asks first).
    RevokeAll,
    /// The previous page of site cards.
    Prev,
    /// The next page of site cards.
    Next,
    /// `연결 해제` of a card of the page shown (the grant that card was drawn for).
    Disconnect(Row),
}
