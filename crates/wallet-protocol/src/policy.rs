use wallet_model::{CanonicalEncode, CodecError, Hash32, Transcript};

/// Runtime distribution channel controlling whether review warnings are overrideable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseChannel {
    /// Self-only signed canary build.
    PrivateCanary,
    /// General mainnet distribution; warning-only exceptions are disabled.
    GeneralMainnet,
}

/// Conditions that are never overrideable by a warning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum InvalidProtocolReason {
    /// Registry signature could not be verified.
    InvalidRegistrySignature = 1,
    /// Registry sequence moved backwards.
    RegistryRollback = 2,
    /// RPC genesis/fingerprint did not match the selected chain.
    ChainFingerprintMismatch = 3,
    /// Transaction envelope is unknown or disabled.
    UnknownEnvelope = 4,
    /// Typed-data schema or digest binding is invalid.
    InvalidTypedDataSchema = 5,
    /// A known active fork rule was violated.
    ActiveRuleViolation = 6,
}

/// Signed protocol-rule review status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolValidity {
    /// Registry and rule coverage are current and verified.
    Verified,
    /// The last signed review expired at the given Unix millisecond.
    ExpiredReview {
        /// Signed review expiration time in Unix milliseconds.
        expired_at_ms: u64,
    },
    /// No adapter rule covers a detected behavior; identifier is non-secret.
    RuleCoverageUnknown {
        /// Stable identifier of the uncovered rule or behavior.
        rule_id: Hash32,
    },
    /// Cryptographic, rollback, fingerprint, schema, envelope, or active-rule failure.
    Invalid(InvalidProtocolReason),
}

/// Enforcement outcome before an approval UI can be launched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolDisposition {
    /// Continue with ordinary approval.
    Allow,
    /// Private-canary-only strong warning and hold confirmation.
    WarnAndHold,
    /// Stop before signing; no UI override is possible.
    Deny,
}

impl ProtocolValidity {
    /// Returns the channel-specific, fail-closed enforcement result.
    #[must_use]
    pub const fn disposition(self, channel: ReleaseChannel) -> ProtocolDisposition {
        match (self, channel) {
            (Self::Verified, _) => ProtocolDisposition::Allow,
            (
                Self::ExpiredReview { .. } | Self::RuleCoverageUnknown { .. },
                ReleaseChannel::PrivateCanary,
            ) => ProtocolDisposition::WarnAndHold,
            (
                Self::ExpiredReview { .. } | Self::RuleCoverageUnknown { .. },
                ReleaseChannel::GeneralMainnet,
            )
            | (Self::Invalid(_), _) => ProtocolDisposition::Deny,
        }
    }
}

impl CanonicalEncode for ProtocolValidity {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        match self {
            Self::Verified => transcript.push_u8(0),
            Self::ExpiredReview { expired_at_ms } => {
                transcript.push_u8(1);
                transcript.push_u64(*expired_at_ms);
            }
            Self::RuleCoverageUnknown { rule_id } => {
                transcript.push_u8(2);
                rule_id.encode(transcript)?;
            }
            Self::Invalid(reason) => {
                transcript.push_u8(3);
                transcript.push_u8(*reason as u8);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{InvalidProtocolReason, ProtocolDisposition, ProtocolValidity, ReleaseChannel};

    #[test]
    fn only_private_canary_can_override_review_staleness() {
        let stale = ProtocolValidity::ExpiredReview { expired_at_ms: 1 };
        assert_eq!(
            stale.disposition(ReleaseChannel::PrivateCanary),
            ProtocolDisposition::WarnAndHold
        );
        assert_eq!(
            stale.disposition(ReleaseChannel::GeneralMainnet),
            ProtocolDisposition::Deny
        );
    }

    #[test]
    fn cryptographic_invalidity_is_never_overrideable() {
        let invalid = ProtocolValidity::Invalid(InvalidProtocolReason::InvalidRegistrySignature);
        for channel in [
            ReleaseChannel::PrivateCanary,
            ReleaseChannel::GeneralMainnet,
        ] {
            assert_eq!(invalid.disposition(channel), ProtocolDisposition::Deny);
        }
    }
}
