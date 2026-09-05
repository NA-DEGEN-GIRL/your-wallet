//! One-shot approval protocol and raw native presentation boundary.
//!
//! Only this small crate may call Win32 UI functions. It has no network, vault,
//! JSON, ABI, browser, or general GUI-toolkit dependency. The wire format never
//! accepts presentation labels: labels and ordering are owned by this frontend.

use std::fmt::{self, Write as _};
use std::io::{self, Read, Write};

pub use approval_wire::{
    ApprovalDisplay, ApprovalRequest, ApprovalResponse, Decision, DisplayField, FieldSemantic,
    OperationKind, RiskLevel, SimulationStatus,
};

/// Maximum bytes accepted from the inherited channel-supervisor request transport.
pub const MAX_REQUEST_BYTES: u64 = approval_wire::MAX_REQUEST_BYTES as u64;

/// Continuous hold duration required for a high-risk approval.
pub const HIGH_RISK_HOLD_MILLISECONDS: u64 = 2_000;

const DISPLAY_ORDER: [FieldSemantic; 31] = [
    FieldSemantic::ProtocolCoverageWarning,
    FieldSemantic::UnknownCalldataWarning,
    FieldSemantic::PersonalMessageWarning,
    FieldSemantic::NoSimulationWarning,
    FieldSemantic::OriginWarning,
    FieldSemantic::Origin,
    FieldSemantic::OriginProvenance,
    FieldSemantic::OperationKind,
    FieldSemantic::NetworkName,
    FieldSemantic::ChainId,
    FieldSemantic::GenesisHash,
    FieldSemantic::RulesetRevision,
    FieldSemantic::RpcObservationsDigest,
    FieldSemantic::Account,
    FieldSemantic::EnvelopeType,
    FieldSemantic::Nonce,
    FieldSemantic::Target,
    FieldSemantic::NativeValue,
    FieldSemantic::GasLimit,
    FieldSemantic::GasPrice,
    FieldSemantic::MaxPriorityFeePerGas,
    FieldSemantic::MaxFeePerGas,
    FieldSemantic::MaximumNetworkFee,
    FieldSemantic::Calldata,
    FieldSemantic::CalldataKeccak256,
    FieldSemantic::AccessList,
    FieldSemantic::PersonalMessageBytes,
    FieldSemantic::SimulationStatus,
    FieldSemantic::SimulationEngine,
    FieldSemantic::SimulationResultDigest,
    FieldSemantic::SimulationInputDigest,
];

/// Approval-channel failure. Details are never returned to an untrusted caller.
pub enum ApprovalError {
    /// Input or output I/O failed.
    Io(io::Error),
    /// The request is invalid or violates a fixed bound.
    Malformed,
    /// Text is not strict UTF-8 or contains forbidden controls.
    InvalidText,
}

impl fmt::Debug for ApprovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Io(_) => "ApprovalError::Io([REDACTED])",
            Self::Malformed => "ApprovalError::Malformed",
            Self::InvalidText => "ApprovalError::InvalidText",
        })
    }
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Io(_) => "approval channel I/O failed",
            Self::Malformed => "approval request is malformed",
            Self::InvalidText => "approval request text is invalid",
        })
    }
}

impl From<io::Error> for ApprovalError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<approval_wire::WireError> for ApprovalError {
    fn from(value: approval_wire::WireError) -> Self {
        match value {
            approval_wire::WireError::InvalidText => Self::InvalidText,
            approval_wire::WireError::Malformed | approval_wire::WireError::TooLarge => {
                Self::Malformed
            }
        }
    }
}

/// Frontend-owned English label for a stable semantic tag.
#[must_use]
pub const fn label_for(semantic: FieldSemantic) -> &'static str {
    match semantic {
        FieldSemantic::Origin => "Requesting site (browser-reported)",
        FieldSemantic::OriginProvenance => "Origin provenance",
        FieldSemantic::Account => "Signing account",
        FieldSemantic::NetworkName => "Network",
        FieldSemantic::ChainId => "Chain ID",
        FieldSemantic::GenesisHash => "Genesis hash",
        FieldSemantic::RulesetRevision => "Rule-set revision",
        FieldSemantic::RpcObservationsDigest => "RPC observations digest",
        FieldSemantic::OperationKind => "Operation",
        FieldSemantic::EnvelopeType => "Transaction envelope type",
        FieldSemantic::Nonce => "Account nonce",
        FieldSemantic::Target => "Recipient or contract creation",
        FieldSemantic::NativeValue => "Native value (exact base units)",
        FieldSemantic::GasLimit => "Gas limit",
        FieldSemantic::GasPrice => "Gas price (exact base units per gas)",
        FieldSemantic::MaxPriorityFeePerGas => "Maximum priority fee per gas",
        FieldSemantic::MaxFeePerGas => "Maximum fee per gas",
        FieldSemantic::MaximumNetworkFee => "Maximum total network fee",
        FieldSemantic::Calldata => "Exact calldata",
        FieldSemantic::CalldataKeccak256 => "Calldata Keccak-256",
        FieldSemantic::AccessList => "Exact access list",
        FieldSemantic::PersonalMessageBytes => "Exact personal-message bytes",
        FieldSemantic::SimulationStatus => "Simulation status",
        FieldSemantic::SimulationEngine => "Simulation engine",
        FieldSemantic::SimulationResultDigest => "Simulation result digest",
        FieldSemantic::SimulationInputDigest => "Simulation input digest",
        FieldSemantic::OriginWarning => "Origin security warning",
        FieldSemantic::PersonalMessageWarning => "Signature security warning",
        FieldSemantic::NoSimulationWarning => "Simulation security warning",
        FieldSemantic::UnknownCalldataWarning => "Calldata security warning",
        FieldSemantic::ProtocolCoverageWarning => "Protocol coverage warning",
    }
}

/// Source currently sustaining a high-risk hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoldSource {
    /// Primary pointer button over the approval control.
    Pointer,
    /// Physical Space key while the approval control owns focus.
    Space,
}

/// Trusted UI event accepted by the pure confirmation state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InteractionEvent {
    /// A monotonic timer update.
    Tick,
    /// An ordinary approval control was explicitly activated.
    ApproveActivated,
    /// Reject, close, or Escape was explicitly activated.
    RejectActivated,
    /// The primary pointer was pressed over the approval control.
    PointerPressed {
        /// Whether the pointer is inside the complete button rectangle.
        inside: bool,
        /// Whether this event also activated the previously inactive window.
        click_through: bool,
        /// The native frontend independently observed physical button-down.
        physical_down: bool,
    },
    /// The captured pointer moved.
    PointerMoved {
        /// Whether the pointer remains inside the complete button rectangle.
        inside: bool,
    },
    /// The primary pointer was released.
    PointerReleased {
        /// Whether the native frontend still observes physical button-down.
        physical_down: bool,
    },
    /// Space was pressed while the approval control owned keyboard focus.
    SpacePressed {
        /// Windows marked the keydown as an auto-repeat.
        repeat: bool,
        /// The native frontend independently observed physical Space-down.
        physical_down: bool,
    },
    /// Space was released.
    SpaceReleased {
        /// Whether the native frontend still observes physical Space-down.
        physical_down: bool,
    },
    /// The approval control or window lost keyboard focus.
    FocusLost,
    /// The approval window ceased to be the foreground window.
    ForegroundLost,
    /// Pointer capture was lost unexpectedly.
    CaptureLost,
    /// Windows cancelled the current input mode.
    CancelMode,
}

/// Terminal or pending state of one approval interaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InteractionStatus {
    /// No terminal decision has been made.
    Pending,
    /// Approval requirements were satisfied.
    Approved,
    /// The user rejected or the trusted time invariant failed/expired.
    Rejected,
}

/// Pure, deterministic one-shot approval interaction state.
///
/// Times are elapsed milliseconds from one trusted monotonic clock selected by
/// the native frontend. A backwards value rejects terminally.
#[derive(Debug)]
pub struct ApprovalInteraction {
    risk: RiskLevel,
    deadline_ms: u64,
    last_now_ms: u64,
    status: InteractionStatus,
    active_hold: Option<(HoldSource, u64)>,
    blocked_inputs: u8,
}

impl ApprovalInteraction {
    /// Create a bounded one-shot interaction.
    ///
    /// # Errors
    ///
    /// Rejects zero/overlong lifetimes or monotonic timestamp overflow.
    pub fn new(
        risk: RiskLevel,
        expires_after_milliseconds: u32,
        now_ms: u64,
    ) -> Result<Self, ApprovalError> {
        if !(1..=approval_wire::MAX_EXPIRY_MILLISECONDS).contains(&expires_after_milliseconds) {
            return Err(ApprovalError::Malformed);
        }
        let deadline_ms = now_ms
            .checked_add(u64::from(expires_after_milliseconds))
            .ok_or(ApprovalError::Malformed)?;
        Ok(Self {
            risk,
            deadline_ms,
            last_now_ms: now_ms,
            status: InteractionStatus::Pending,
            active_hold: None,
            blocked_inputs: 0,
        })
    }

    /// Apply one trusted UI event at a monotonic timestamp.
    pub fn apply(&mut self, now_ms: u64, event: InteractionEvent) -> InteractionStatus {
        if self.status != InteractionStatus::Pending {
            return self.status;
        }
        if now_ms < self.last_now_ms {
            self.reject();
            return self.status;
        }
        self.last_now_ms = now_ms;
        if now_ms >= self.deadline_ms {
            self.reject();
            return self.status;
        }

        if self.resets_before_completion(event) {
            self.reset_for_event(event);
            return self.status;
        }

        if self.hold_completed(now_ms) {
            self.approve();
            return self.status;
        }

        match event {
            InteractionEvent::ApproveActivated => {
                if self.risk == RiskLevel::Standard {
                    self.approve();
                }
            }
            InteractionEvent::RejectActivated => self.reject(),
            InteractionEvent::PointerPressed {
                inside,
                click_through,
                physical_down: true,
            } => {
                if click_through || !inside {
                    self.block(HoldSource::Pointer);
                } else {
                    self.begin_hold(HoldSource::Pointer, now_ms);
                }
            }
            InteractionEvent::PointerReleased {
                physical_down: false,
            } => {
                self.release_source(HoldSource::Pointer);
            }
            InteractionEvent::SpacePressed {
                repeat: false,
                physical_down: true,
            } => {
                self.begin_hold(HoldSource::Space, now_ms);
            }
            InteractionEvent::SpaceReleased {
                physical_down: false,
            } => {
                self.release_source(HoldSource::Space);
            }
            InteractionEvent::Tick
            | InteractionEvent::PointerMoved { .. }
            | InteractionEvent::PointerPressed { .. }
            | InteractionEvent::PointerReleased { .. }
            | InteractionEvent::SpacePressed { .. }
            | InteractionEvent::SpaceReleased { .. }
            | InteractionEvent::FocusLost
            | InteractionEvent::ForegroundLost
            | InteractionEvent::CaptureLost
            | InteractionEvent::CancelMode => {
                // Handled by `resets_before_completion` above.
            }
        }
        self.status
    }

    /// Current terminal or pending status.
    #[must_use]
    pub const fn status(&self) -> InteractionStatus {
        self.status
    }

    /// Source currently sustaining a hold, if any.
    #[must_use]
    pub const fn hold_source(&self) -> Option<HoldSource> {
        match self.active_hold {
            Some((source, _)) => Some(source),
            None => None,
        }
    }

    /// Whether a source must be physically released before it can start again.
    #[must_use]
    pub const fn is_blocked(&self, source: HoldSource) -> bool {
        self.blocked_inputs & source.bit() != 0
    }

    /// Milliseconds remaining in an active high-risk hold.
    #[must_use]
    pub fn hold_remaining_ms(&self, now_ms: u64) -> Option<u64> {
        self.active_hold.map(|(_, started_ms)| {
            HIGH_RISK_HOLD_MILLISECONDS.saturating_sub(now_ms.saturating_sub(started_ms))
        })
    }

    /// Milliseconds remaining before the whole prompt expires.
    #[must_use]
    pub const fn lifetime_remaining_ms(&self, now_ms: u64) -> u64 {
        self.deadline_ms.saturating_sub(now_ms)
    }

    fn begin_hold(&mut self, source: HoldSource, now_ms: u64) {
        if self.active_hold.is_none() && !self.is_blocked(source) {
            self.active_hold = Some((source, now_ms));
        }
    }

    fn release_source(&mut self, source: HoldSource) {
        if self.risk == RiskLevel::Standard && self.hold_source() == Some(source) {
            self.approve();
            return;
        }
        self.clear_hold(source);
        self.unblock(source);
    }

    fn hold_completed(&self, now_ms: u64) -> bool {
        self.risk == RiskLevel::High
            && self.active_hold.is_some_and(|(_, started_ms)| {
                now_ms.saturating_sub(started_ms) >= HIGH_RISK_HOLD_MILLISECONDS
            })
    }

    fn reset_for_event(&mut self, event: InteractionEvent) {
        match event {
            InteractionEvent::PointerMoved { inside: false } | InteractionEvent::CaptureLost => {
                self.reset_source(HoldSource::Pointer);
            }
            InteractionEvent::PointerPressed { .. } | InteractionEvent::PointerReleased { .. } => {
                self.reset_input_attempt(HoldSource::Pointer);
            }
            InteractionEvent::SpacePressed { .. } | InteractionEvent::SpaceReleased { .. } => {
                self.reset_input_attempt(HoldSource::Space);
            }
            InteractionEvent::FocusLost
            | InteractionEvent::ForegroundLost
            | InteractionEvent::CancelMode => {
                if let Some((source, _)) = self.active_hold {
                    self.reset_source(source);
                }
            }
            _ => {}
        }
    }

    fn reset_source(&mut self, source: HoldSource) {
        self.clear_hold(source);
        self.block(source);
    }

    fn reset_input_attempt(&mut self, attempted_source: HoldSource) {
        if let Some((active_source, _)) = self.active_hold {
            self.reset_source(active_source);
        }
        self.block(attempted_source);
    }

    fn clear_hold(&mut self, source: HoldSource) {
        if self.hold_source() == Some(source) {
            self.active_hold = None;
        }
    }

    fn block(&mut self, source: HoldSource) {
        self.blocked_inputs |= source.bit();
    }

    fn unblock(&mut self, source: HoldSource) {
        self.blocked_inputs &= !source.bit();
    }

    fn approve(&mut self) {
        self.active_hold = None;
        self.status = InteractionStatus::Approved;
    }

    fn reject(&mut self) {
        self.active_hold = None;
        self.status = InteractionStatus::Rejected;
    }

    fn resets_before_completion(&self, event: InteractionEvent) -> bool {
        match event {
            InteractionEvent::PointerMoved { inside: false }
            | InteractionEvent::FocusLost
            | InteractionEvent::ForegroundLost
            | InteractionEvent::CaptureLost
            | InteractionEvent::CancelMode => true,
            InteractionEvent::PointerPressed {
                inside,
                click_through,
                physical_down,
            } => !inside || click_through || !physical_down || self.hold_source().is_some(),
            InteractionEvent::PointerReleased { physical_down }
            | InteractionEvent::SpaceReleased { physical_down } => physical_down,
            InteractionEvent::SpacePressed {
                repeat,
                physical_down,
            } => {
                !physical_down
                    || (repeat && self.hold_source() != Some(HoldSource::Space))
                    || (!repeat && self.hold_source().is_some())
            }
            _ => false,
        }
    }
}

impl HoldSource {
    const fn bit(self) -> u8 {
        match self {
            Self::Pointer => 1,
            Self::Space => 2,
        }
    }
}

/// Decode a single bounded request from an inherited stream.
///
/// # Errors
///
/// Returns an I/O error or rejects malformed, oversized, or invalid text input.
pub fn read_request(reader: &mut impl Read) -> Result<ApprovalRequest, ApprovalError> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(ApprovalError::Io)?;
    if bytes.len() > usize::try_from(MAX_REQUEST_BYTES).map_err(|_| ApprovalError::Malformed)? {
        return Err(ApprovalError::Malformed);
    }
    approval_wire::decode_request(&bytes).map_err(ApprovalError::from)
}

/// Encode the only response shape accepted by the authenticated parent verifier.
///
/// # Errors
///
/// Returns an I/O error if the fixed response cannot be written and flushed.
pub fn write_response(
    writer: &mut impl Write,
    response: ApprovalResponse,
) -> Result<(), ApprovalError> {
    let bytes = approval_wire::encode_response(response);
    writer.write_all(&bytes).map_err(ApprovalError::Io)?;
    writer.flush().map_err(ApprovalError::Io)
}

/// Build exact plain native UI text using fixed labels and ordering.
///
/// No value is truncated, interpreted as rich text, or used as a format string.
///
/// # Errors
///
/// Returns an error if the request violates any structural or text invariant.
pub fn render_plain_text(request: &ApprovalRequest) -> Result<String, ApprovalError> {
    let mut output = String::with_capacity(4_096);
    output.push_str("Verify every field below. Values are exact and may wrap; scroll to inspect all content.\r\n\r\n");
    for semantic in DISPLAY_ORDER {
        if let Some(field) = request.display().field(semantic) {
            let critical_marker = if field.security_critical() {
                " [security-critical]"
            } else {
                ""
            };
            write!(
                &mut output,
                "{}{critical_marker}:\r\n{}\r\n\r\n",
                label_for(semantic),
                field.value()
            )
            .map_err(|_| ApprovalError::Malformed)?;
        }
    }
    Ok(output)
}

#[cfg(windows)]
mod native;

/// Present the platform-native one-shot approval surface.
///
/// The Windows implementation uses a dedicated one-shot window. Other targets
/// reject because the product scope does not define a trusted UI there.
///
/// # Errors
///
/// Returns an error if the request is invalid or the native UI cannot be built.
pub fn present(request: &ApprovalRequest) -> Result<Decision, ApprovalError> {
    #[cfg(windows)]
    {
        native::present(request)
    }
    #[cfg(not(windows))]
    {
        let _ = request;
        Ok(Decision::Reject)
    }
}

/// Presents the debug service transport probe with an explicit no-signing title.
///
/// This native UI is not release or signing evidence. Its relative visual timer
/// cannot extend the retained service deadline: the child checks that deadline
/// around presentation, while the service enforces it and terminates late UI.
///
/// # Errors
/// Returns an error if the request or native window cannot be constructed.
#[cfg(all(
    windows,
    target_arch = "x86_64",
    target_env = "msvc",
    debug_assertions,
    feature = "service-helper-rpc-probe-feasibility-test-hook"
))]
pub fn present_service_probe(request: &ApprovalRequest) -> Result<Decision, ApprovalError> {
    native::present_service_probe(request)
}

#[cfg(test)]
mod tests {
    use super::{
        ApprovalDisplay, ApprovalError, ApprovalInteraction, ApprovalRequest, ApprovalResponse,
        Decision, DisplayField, FieldSemantic, HoldSource, InteractionEvent, InteractionStatus,
        OperationKind, RiskLevel, SimulationStatus, label_for, render_plain_text, write_response,
    };

    fn field(semantic: FieldSemantic, value: &str) -> Result<DisplayField, ApprovalError> {
        DisplayField::new(semantic, value, semantic != FieldSemantic::SimulationEngine)
            .map_err(ApprovalError::from)
    }

    fn valid_request() -> Result<ApprovalRequest, ApprovalError> {
        let display = ApprovalDisplay::new(
            RiskLevel::High,
            vec![
                field(
                    FieldSemantic::NoSimulationWarning,
                    "No simulation was performed.",
                )?,
                field(FieldSemantic::Origin, "https://example.test")?,
                field(
                    FieldSemantic::PersonalMessageWarning,
                    "Personal signatures can be reused by protocols.",
                )?,
                field(
                    FieldSemantic::Account,
                    "0x1111111111111111111111111111111111111111",
                )?,
                field(FieldSemantic::NetworkName, "Ethereum")?,
                field(FieldSemantic::ChainId, "1")?,
                field(
                    FieldSemantic::GenesisHash,
                    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )?,
                field(
                    FieldSemantic::RulesetRevision,
                    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )?,
                field(
                    FieldSemantic::RpcObservationsDigest,
                    "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                )?,
                field(
                    FieldSemantic::OperationKind,
                    OperationKind::PersonalMessage.value(),
                )?,
                field(FieldSemantic::PersonalMessageBytes, "0x0102")?,
                field(
                    FieldSemantic::SimulationStatus,
                    SimulationStatus::NotPerformed.value(),
                )?,
                field(
                    FieldSemantic::OriginProvenance,
                    "Browser-reported; not independently verified",
                )?,
                field(
                    FieldSemantic::OriginWarning,
                    "Browser origin is not independently attested.",
                )?,
            ],
        )
        .map_err(ApprovalError::from)?;
        ApprovalRequest::new([7; 32], [9; 32], 120_000, "blue comet", display)
            .map_err(ApprovalError::from)
    }

    #[test]
    fn approval_error_formatting_never_repeats_io_details() {
        let error = ApprovalError::Io(std::io::Error::other("private-local-path-marker"));
        assert_eq!(format!("{error:?}"), "ApprovalError::Io([REDACTED])");
        assert_eq!(error.to_string(), "approval channel I/O failed");
        assert!(!format!("{error:?}").contains("private-local-path-marker"));
        assert!(!error.to_string().contains("private-local-path-marker"));
    }

    #[test]
    fn parses_bounded_typed_request_with_frontend_labels() -> Result<(), ApprovalError> {
        let request = valid_request()?;
        let rendered = render_plain_text(&request)?;
        assert!(rendered.contains("Signing account [security-critical]:\r\n0x1111"));
        assert!(!rendered.contains("caller label"));
        Ok(())
    }

    #[test]
    fn warnings_render_before_origin_using_frontend_owned_labels() -> Result<(), ApprovalError> {
        let request = valid_request()?;
        let rendered = render_plain_text(&request)?;
        let warning = rendered
            .find(label_for(FieldSemantic::PersonalMessageWarning))
            .unwrap_or(usize::MAX);
        let origin = rendered.find(label_for(FieldSemantic::Origin)).unwrap_or(0);
        assert!(warning < origin);
        Ok(())
    }

    #[test]
    fn standard_requires_explicit_activation() -> Result<(), ApprovalError> {
        let mut interaction = ApprovalInteraction::new(RiskLevel::Standard, 30_000, 100)?;
        assert_eq!(
            interaction.apply(20_000, InteractionEvent::Tick),
            InteractionStatus::Pending
        );
        assert_eq!(
            interaction.apply(20_001, InteractionEvent::ApproveActivated),
            InteractionStatus::Approved
        );
        Ok(())
    }

    #[test]
    fn standard_pointer_release_requires_a_matching_press() -> Result<(), ApprovalError> {
        let mut interaction = ApprovalInteraction::new(RiskLevel::Standard, 30_000, 0)?;
        assert_eq!(
            interaction.apply(
                10,
                InteractionEvent::PointerReleased {
                    physical_down: false,
                },
            ),
            InteractionStatus::Pending
        );
        interaction.apply(
            20,
            InteractionEvent::PointerPressed {
                inside: true,
                click_through: false,
                physical_down: true,
            },
        );
        assert_eq!(
            interaction.apply(
                21,
                InteractionEvent::PointerReleased {
                    physical_down: false,
                },
            ),
            InteractionStatus::Approved
        );
        Ok(())
    }

    #[test]
    fn inconsistent_physical_input_cannot_approve_standard() -> Result<(), ApprovalError> {
        let mut pointer = ApprovalInteraction::new(RiskLevel::Standard, 30_000, 0)?;
        pointer.apply(
            10,
            InteractionEvent::PointerPressed {
                inside: true,
                click_through: false,
                physical_down: false,
            },
        );
        assert!(pointer.is_blocked(HoldSource::Pointer));
        assert_eq!(
            pointer.apply(
                11,
                InteractionEvent::PointerReleased {
                    physical_down: false,
                },
            ),
            InteractionStatus::Pending
        );

        let mut keyboard = ApprovalInteraction::new(RiskLevel::Standard, 30_000, 0)?;
        keyboard.apply(
            20,
            InteractionEvent::SpacePressed {
                repeat: false,
                physical_down: true,
            },
        );
        assert_eq!(
            keyboard.apply(
                21,
                InteractionEvent::SpaceReleased {
                    physical_down: true,
                },
            ),
            InteractionStatus::Pending
        );
        assert!(keyboard.is_blocked(HoldSource::Space));
        Ok(())
    }

    #[test]
    fn high_risk_ignores_ordinary_activation() -> Result<(), ApprovalError> {
        let mut interaction = ApprovalInteraction::new(RiskLevel::High, 30_000, 0)?;
        assert_eq!(
            interaction.apply(10, InteractionEvent::ApproveActivated),
            InteractionStatus::Pending
        );
        Ok(())
    }

    #[test]
    fn high_risk_requires_full_continuous_pointer_hold() -> Result<(), ApprovalError> {
        let mut interaction = ApprovalInteraction::new(RiskLevel::High, 30_000, 0)?;
        interaction.apply(
            100,
            InteractionEvent::PointerPressed {
                inside: true,
                click_through: false,
                physical_down: true,
            },
        );
        assert_eq!(interaction.hold_source(), Some(HoldSource::Pointer));
        assert_eq!(
            interaction.apply(2_099, InteractionEvent::Tick),
            InteractionStatus::Pending
        );
        assert_eq!(
            interaction.apply(2_100, InteractionEvent::Tick),
            InteractionStatus::Approved
        );
        Ok(())
    }

    #[test]
    fn pointer_outside_and_focus_loss_reset_and_require_release() -> Result<(), ApprovalError> {
        let mut interaction = ApprovalInteraction::new(RiskLevel::High, 30_000, 0)?;
        interaction.apply(
            100,
            InteractionEvent::PointerPressed {
                inside: true,
                click_through: false,
                physical_down: true,
            },
        );
        interaction.apply(1_500, InteractionEvent::PointerMoved { inside: false });
        assert!(interaction.is_blocked(HoldSource::Pointer));
        interaction.apply(
            1_600,
            InteractionEvent::PointerPressed {
                inside: true,
                click_through: false,
                physical_down: true,
            },
        );
        assert_eq!(interaction.hold_source(), None);
        interaction.apply(
            1_700,
            InteractionEvent::PointerReleased {
                physical_down: false,
            },
        );
        interaction.apply(
            1_800,
            InteractionEvent::PointerPressed {
                inside: true,
                click_through: false,
                physical_down: true,
            },
        );
        interaction.apply(3_000, InteractionEvent::FocusLost);
        assert_eq!(interaction.hold_source(), None);
        assert!(interaction.is_blocked(HoldSource::Pointer));
        Ok(())
    }

    #[test]
    fn space_repeat_resets_hold_until_physical_release() -> Result<(), ApprovalError> {
        let mut interaction = ApprovalInteraction::new(RiskLevel::High, 30_000, 0)?;
        interaction.apply(
            100,
            InteractionEvent::SpacePressed {
                repeat: false,
                physical_down: true,
            },
        );
        interaction.apply(
            500,
            InteractionEvent::SpacePressed {
                repeat: true,
                physical_down: false,
            },
        );
        assert_eq!(interaction.hold_source(), None);
        assert!(interaction.is_blocked(HoldSource::Space));
        interaction.apply(
            700,
            InteractionEvent::SpacePressed {
                repeat: false,
                physical_down: true,
            },
        );
        assert_eq!(interaction.hold_source(), None);
        interaction.apply(
            800,
            InteractionEvent::SpaceReleased {
                physical_down: false,
            },
        );
        interaction.apply(
            900,
            InteractionEvent::SpacePressed {
                repeat: false,
                physical_down: true,
            },
        );
        assert_eq!(interaction.hold_source(), Some(HoldSource::Space));
        assert_eq!(
            interaction.apply(2_900, InteractionEvent::Tick),
            InteractionStatus::Approved
        );
        Ok(())
    }

    #[test]
    fn physical_space_repeat_neither_shortens_nor_extends_hold() -> Result<(), ApprovalError> {
        let mut interaction = ApprovalInteraction::new(RiskLevel::High, 30_000, 0)?;
        interaction.apply(
            100,
            InteractionEvent::SpacePressed {
                repeat: false,
                physical_down: true,
            },
        );
        interaction.apply(
            700,
            InteractionEvent::SpacePressed {
                repeat: true,
                physical_down: true,
            },
        );
        interaction.apply(
            1_500,
            InteractionEvent::SpacePressed {
                repeat: true,
                physical_down: true,
            },
        );
        assert_eq!(interaction.hold_remaining_ms(2_099), Some(1));
        assert_eq!(
            interaction.apply(2_099, InteractionEvent::Tick),
            InteractionStatus::Pending
        );
        assert_eq!(
            interaction.apply(2_100, InteractionEvent::Tick),
            InteractionStatus::Approved
        );
        Ok(())
    }

    #[test]
    fn stray_space_repeat_is_blocked_until_keyup() -> Result<(), ApprovalError> {
        let mut interaction = ApprovalInteraction::new(RiskLevel::High, 30_000, 0)?;
        interaction.apply(
            100,
            InteractionEvent::SpacePressed {
                repeat: true,
                physical_down: true,
            },
        );
        assert_eq!(interaction.hold_source(), None);
        assert!(interaction.is_blocked(HoldSource::Space));
        interaction.apply(
            200,
            InteractionEvent::SpaceReleased {
                physical_down: false,
            },
        );
        assert!(!interaction.is_blocked(HoldSource::Space));
        Ok(())
    }

    #[test]
    fn click_through_never_starts_a_hold() -> Result<(), ApprovalError> {
        let mut interaction = ApprovalInteraction::new(RiskLevel::High, 30_000, 0)?;
        interaction.apply(
            100,
            InteractionEvent::PointerPressed {
                inside: true,
                click_through: true,
                physical_down: true,
            },
        );
        assert_eq!(interaction.hold_source(), None);
        assert!(interaction.is_blocked(HoldSource::Pointer));
        assert_eq!(
            interaction.apply(5_000, InteractionEvent::Tick),
            InteractionStatus::Pending
        );
        Ok(())
    }

    #[test]
    fn expiry_and_backwards_time_reject_terminally() -> Result<(), ApprovalError> {
        let mut expired = ApprovalInteraction::new(RiskLevel::High, 1_000, 500)?;
        expired.apply(
            1_499,
            InteractionEvent::SpacePressed {
                repeat: false,
                physical_down: true,
            },
        );
        assert_eq!(
            expired.apply(1_500, InteractionEvent::Tick),
            InteractionStatus::Rejected
        );
        let mut backwards = ApprovalInteraction::new(RiskLevel::Standard, 30_000, 500)?;
        assert_eq!(
            backwards.apply(499, InteractionEvent::ApproveActivated),
            InteractionStatus::Rejected
        );
        Ok(())
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_present_fails_closed() -> Result<(), ApprovalError> {
        let request = valid_request()?;
        assert_eq!(super::present(&request)?, Decision::Reject);
        Ok(())
    }

    #[test]
    fn response_is_fixed_shape_and_versioned() -> Result<(), ApprovalError> {
        let request = valid_request()?;
        let response = ApprovalResponse::for_request(Decision::Reject, &request);
        let mut bytes = Vec::new();
        write_response(&mut bytes, response)?;
        assert_eq!(bytes, approval_wire::encode_response(response));
        Ok(())
    }
}
