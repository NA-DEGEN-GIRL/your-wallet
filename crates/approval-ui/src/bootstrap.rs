//! Earliest child-side Approval runtime bootstrap.

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub(super) use windows::{seal_inherited_approval_stdio, set_binary_stdio};

#[cfg(not(windows))]
#[must_use = "binary mode requires the sealed Approval stdio proof"]
pub(super) struct SealedApprovalStdio {
    _private: (),
}

#[cfg(not(windows))]
pub(super) fn seal_inherited_approval_stdio()
-> Result<SealedApprovalStdio, approval_ui::ApprovalError> {
    Ok(SealedApprovalStdio { _private: () })
}

#[cfg(not(windows))]
pub(super) fn set_binary_stdio(
    _sealed: &SealedApprovalStdio,
) -> Result<(), approval_ui::ApprovalError> {
    Ok(())
}
