//! Earliest child-side Approval runtime bootstrap.

#[cfg(windows)]
mod windows;

/// One request released only after the inherited Windows parent, child sandbox,
/// proof handles, nonce exchange, and exact request hash are authenticated.
///
/// The private field prevents raw or legacy request bytes from reaching the UI
/// without crossing the complete bootstrap boundary first.
#[must_use = "the authenticated Approval request must be presented or rejected"]
pub(super) struct AuthenticatedApprovalRequest {
    request: approval_ui::ApprovalRequest,
}

impl core::fmt::Debug for AuthenticatedApprovalRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthenticatedApprovalRequest([REDACTED])")
    }
}

impl AuthenticatedApprovalRequest {
    #[cfg(windows)]
    const fn new(request: approval_ui::ApprovalRequest) -> Self {
        Self { request }
    }

    pub(super) const fn request(&self) -> &approval_ui::ApprovalRequest {
        &self.request
    }
}

/// Authenticates the inherited parent and returns exactly one bound request.
///
/// Non-Windows builds deliberately have no compatibility or raw-stream path.
pub(super) fn authenticate_inherited_parent()
-> Result<AuthenticatedApprovalRequest, approval_ui::ApprovalError> {
    #[cfg(windows)]
    {
        windows::authenticate_request()
    }
    #[cfg(not(windows))]
    {
        Err(std::io::Error::other("Approval parent authentication failed").into())
    }
}
