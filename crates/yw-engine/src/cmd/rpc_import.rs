//! Presses of the `rpc.json에서 가져오기` card of settings → 네트워크(RPC) (`app_rpc_import` on
//! Windows; spec/04 §2.11). The file itself is read and deleted by the shell (2026-11-20, S4
//! P1: owner decision O-13 keeps it there with no platform trait; it was "S4: behind a
//! platform trait").
//!
//! 2026-11-18 (S3 C5): created.

/// An `rpc.json` import press.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcImportPress {
    /// `rpc.json에서 가져오기`.
    Import,
    /// The import confirmation's `덮어쓰기` / `가져오기`.
    Overwrite,
    /// The import confirmation's `비어 있는 네트워크만`.
    Fill,
    /// The import confirmation's `취소`.
    Cancel,
    /// `rpc.json 지우기…` (asks first).
    Delete,
    /// Its confirmation `지우기`.
    DeleteConfirm,
    /// Its confirmation `취소`.
    DeleteCancel,
}
