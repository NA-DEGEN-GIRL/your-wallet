use core::fmt;

use crate::{BoundedText, CanonicalEncode, CodecError, Hash32, ParseValueError, Transcript};

const MAX_ORIGIN_BYTES: usize = 2_048;
const MAX_DOCUMENT_ID_BYTES: usize = 256;
const MAX_EXTENSION_ID_BYTES: usize = 64;

/// Browser-context validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserContextError {
    /// The origin is not a serialized HTTP(S) origin.
    InvalidOrigin,
    /// A bounded field was malformed.
    InvalidField(ParseValueError),
    /// Sequence zero is reserved and cannot identify a request.
    ZeroSequence,
    /// The provenance is not eligible for a version-1 signing request.
    UnsupportedSigningContext,
}

impl fmt::Display for BrowserContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidOrigin => "invalid browser origin",
            Self::InvalidField(_) => "invalid bounded browser field",
            Self::ZeroSequence => "browser sequence must be non-zero",
            Self::UnsupportedSigningContext => "unsupported browser signing context",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for BrowserContextError {}

impl From<ParseValueError> for BrowserContextError {
    fn from(value: ParseValueError) -> Self {
        Self::InvalidField(value)
    }
}

/// A serialized browser origin with no path, credentials, query, or fragment.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BrowserOrigin(BoundedText<MAX_ORIGIN_BYTES>);

impl fmt::Debug for BrowserOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BrowserOrigin([REDACTED])")
    }
}

impl BrowserOrigin {
    /// Validates an HTTP(S) serialized origin.
    pub fn new(value: impl Into<String>) -> Result<Self, BrowserContextError> {
        let text = BoundedText::new(value)?;
        let origin = text.as_str();
        if !origin.is_ascii() {
            return Err(BrowserContextError::InvalidOrigin);
        }
        let authority = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .ok_or(BrowserContextError::InvalidOrigin)?;
        if authority.is_empty()
            || authority.contains(['/', '?', '#', '@'])
            || authority.starts_with('.')
            || authority.ends_with('.')
        {
            return Err(BrowserContextError::InvalidOrigin);
        }
        validate_authority(authority)?;
        Ok(Self(text))
    }

    /// Returns the canonical serialized origin.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

fn validate_authority(authority: &str) -> Result<(), BrowserContextError> {
    if authority.starts_with('[') {
        let Some(closing_bracket) = authority.find(']') else {
            return Err(BrowserContextError::InvalidOrigin);
        };
        let host = &authority[1..closing_bracket];
        if host.is_empty()
            || !host
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b':' || byte == b'.')
        {
            return Err(BrowserContextError::InvalidOrigin);
        }
        let suffix = &authority[closing_bracket + 1..];
        if !suffix.is_empty() && !valid_port_suffix(suffix) {
            return Err(BrowserContextError::InvalidOrigin);
        }
        return Ok(());
    }

    if authority.matches(':').count() > 1 {
        return Err(BrowserContextError::InvalidOrigin);
    }
    let (host, suffix) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if host.is_empty()
        || !host.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'.'
        })
        || host
            .split('.')
            .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
        || suffix.is_some_and(|port| !valid_decimal_port(port))
    {
        return Err(BrowserContextError::InvalidOrigin);
    }
    Ok(())
}

fn valid_port_suffix(suffix: &str) -> bool {
    suffix.strip_prefix(':').is_some_and(valid_decimal_port)
}

fn valid_decimal_port(port: &str) -> bool {
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    port.parse::<u16>().is_ok_and(|value| value != 0)
}

impl CanonicalEncode for BrowserOrigin {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        self.0.encode(transcript)
    }
}

/// Browser-generated document identity.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DocumentId(BoundedText<MAX_DOCUMENT_ID_BYTES>);

impl fmt::Debug for DocumentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DocumentId([REDACTED])")
    }
}

impl DocumentId {
    /// Validates a non-empty document identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, BrowserContextError> {
        let value = BoundedText::new(value)?;
        if value.as_str().is_empty() {
            return Err(BrowserContextError::InvalidField(
                ParseValueError::InvalidLength,
            ));
        }
        Ok(Self(value))
    }

    /// Returns the identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl CanonicalEncode for DocumentId {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        self.0.encode(transcript)
    }
}

macro_rules! fixed_id {
    ($name:ident, $length:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; $length]);

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }

        impl $name {
            /// Creates an identifier from cryptographically random bytes supplied by the caller.
            #[must_use]
            pub const fn new(bytes: [u8; $length]) -> Self {
                Self(bytes)
            }

            /// Returns the exact identifier bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }
        }

        impl CanonicalEncode for $name {
            fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
                transcript.push_bytes(&self.0)
            }
        }
    };
}

fixed_id!(
    SessionId,
    32,
    "A connection-scoped random browser/native session identifier."
);
fixed_id!(RequestId, 16, "A random request identifier.");
fixed_id!(NonceLeaseId, 16, "A random nonce-reservation identifier.");
fixed_id!(
    ProfileInstallId,
    32,
    "A random browser-profile installation identifier."
);
fixed_id!(
    ActivationNonce,
    32,
    "A random nonce proving a fresh user activation event."
);
fixed_id!(
    ChannelNonce,
    32,
    "A random content-script/page channel binding nonce."
);

/// Browser implementation family admitted by this build.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum BrowserFamily {
    /// Google Chrome Stable.
    Chrome = 1,
    /// Other Chromium-family browser; not enabled for version-1 signing.
    Chromium = 2,
}

impl CanonicalEncode for BrowserFamily {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        transcript.push_u8(*self as u8);
        Ok(())
    }
}

/// Browser-reported lifecycle of the request document.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum DocumentLifecycle {
    /// Document is active and eligible for signing.
    Active = 1,
    /// Document is held in back/forward cache.
    Cached = 2,
    /// Document is unloading or replaced.
    Discarded = 3,
}

impl CanonicalEncode for DocumentLifecycle {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        transcript.push_u8(*self as u8);
        Ok(())
    }
}

/// Trust classification of browser provenance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum BrowserProvenance {
    /// Browser extension reported the fields; Chrome did not attest them.
    BrowserReportedUnverified = 1,
}

impl CanonicalEncode for BrowserProvenance {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        transcript.push_u8(*self as u8);
        Ok(())
    }
}

/// Lowercase Chrome extension identifier.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExtensionId(BoundedText<MAX_EXTENSION_ID_BYTES>);

impl fmt::Debug for ExtensionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExtensionId([REDACTED])")
    }
}

impl ExtensionId {
    /// Validates a Chrome extension ID (`a` through `p`, exactly 32 characters).
    pub fn new(value: impl Into<String>) -> Result<Self, BrowserContextError> {
        let value = BoundedText::new(value)?;
        if value.as_str().len() != 32
            || !value
                .as_str()
                .bytes()
                .all(|byte| matches!(byte, b'a'..=b'p'))
        {
            return Err(BrowserContextError::InvalidField(
                ParseValueError::InvalidEncoding,
            ));
        }
        Ok(Self(value))
    }

    /// Returns the validated ID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl CanonicalEncode for ExtensionId {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        self.0.encode(transcript)
    }
}

/// Browser provenance bound to an approval.
#[derive(Clone, Eq, PartialEq)]
pub struct BrowserContext {
    /// Browser implementation family.
    pub browser_family: BrowserFamily,
    /// Random browser-profile installation identifier.
    pub profile_install_id: ProfileInstallId,
    /// Installed extension identity.
    pub extension_id: ExtensionId,
    /// Chrome tab identifier.
    pub tab_id: u64,
    /// Chrome frame identifier.
    pub frame_id: u64,
    /// Document identity, changing on every navigation.
    pub document_id: DocumentId,
    /// Fresh activation-event nonce.
    pub activation_nonce: ActivationNonce,
    /// Top-level serialized origin.
    pub top_origin: BrowserOrigin,
    /// Requesting-frame serialized origin.
    pub frame_origin: BrowserOrigin,
    /// Browser-reported document lifecycle.
    pub document_lifecycle: DocumentLifecycle,
    /// Content-script/page port binding.
    pub channel_nonce: ChannelNonce,
    /// Explicit provenance trust classification.
    pub provenance: BrowserProvenance,
    /// Native messaging session.
    pub session_id: SessionId,
    /// Strictly increasing per-session sequence.
    pub sequence: u64,
    /// Absolute request deadline in Unix milliseconds.
    pub deadline_ms: u64,
    /// End-to-end request identifier.
    pub request_id: RequestId,
}

impl fmt::Debug for BrowserContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserContext")
            .field("browser_family", &self.browser_family)
            .field("profile_install_id", &"[REDACTED]")
            .field("extension_id", &"[REDACTED]")
            .field("tab_id", &"[REDACTED]")
            .field("frame_id", &"[REDACTED]")
            .field("document_id", &"[REDACTED]")
            .field("activation_nonce", &"[REDACTED]")
            .field("top_origin", &"[REDACTED]")
            .field("frame_origin", &"[REDACTED]")
            .field("document_lifecycle", &self.document_lifecycle)
            .field("channel_nonce", &"[REDACTED]")
            .field("provenance", &self.provenance)
            .field("session_id", &"[REDACTED]")
            .field("sequence", &"[REDACTED]")
            .field("deadline_ms", &"[REDACTED]")
            .field("request_id", &"[REDACTED]")
            .finish()
    }
}

impl BrowserContext {
    /// Checks invariants not expressible by field types.
    pub fn validate(&self) -> Result<(), BrowserContextError> {
        if self.sequence == 0 {
            return Err(BrowserContextError::ZeroSequence);
        }
        let all_zero = |bytes: &[u8; 32]| bytes.iter().all(|byte| *byte == 0);
        if self.browser_family != BrowserFamily::Chrome
            || self.frame_id != 0
            || self.top_origin != self.frame_origin
            || !self.top_origin.as_str().starts_with("https://")
            || self.document_lifecycle != DocumentLifecycle::Active
            || self.provenance != BrowserProvenance::BrowserReportedUnverified
            || all_zero(self.profile_install_id.as_bytes())
            || all_zero(self.activation_nonce.as_bytes())
            || all_zero(self.channel_nonce.as_bytes())
        {
            return Err(BrowserContextError::UnsupportedSigningContext);
        }
        Ok(())
    }
}

impl CanonicalEncode for BrowserContext {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        self.browser_family.encode(transcript)?;
        self.profile_install_id.encode(transcript)?;
        self.extension_id.encode(transcript)?;
        transcript.push_u64(self.tab_id);
        transcript.push_u64(self.frame_id);
        self.document_id.encode(transcript)?;
        self.activation_nonce.encode(transcript)?;
        self.top_origin.encode(transcript)?;
        self.frame_origin.encode(transcript)?;
        self.document_lifecycle.encode(transcript)?;
        self.channel_nonce.encode(transcript)?;
        self.provenance.encode(transcript)?;
        self.session_id.encode(transcript)?;
        transcript.push_u64(self.sequence);
        transcript.push_u64(self.deadline_ms);
        self.request_id.encode(transcript)
    }
}

/// Engine that produced a simulation result.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum SimulationEngine {
    /// Deterministic local EVM execution.
    LocalEvm = 1,
    /// Remote trace method with RPC provenance.
    RpcTrace = 2,
}

/// Exact simulation evidence shown during approval.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum SimulationProvenance {
    /// No simulation was attempted; the UI must say so explicitly.
    NotPerformed,
    /// Simulation completed and its canonical result is identified by a digest.
    Performed {
        /// Simulation engine.
        engine: SimulationEngine,
        /// Digest of the canonical simulation output.
        result_digest: Hash32,
        /// Digest of the RPC/block inputs used by the engine.
        input_digest: Hash32,
    },
}

impl fmt::Debug for SimulationProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPerformed => formatter.write_str("SimulationProvenance::NotPerformed"),
            Self::Performed { engine, .. } => formatter
                .debug_struct("SimulationProvenance::Performed")
                .field("engine", engine)
                .field("result_digest", &"[REDACTED]")
                .field("input_digest", &"[REDACTED]")
                .finish(),
        }
    }
}

impl CanonicalEncode for SimulationProvenance {
    fn encode(&self, transcript: &mut Transcript) -> Result<(), CodecError> {
        match self {
            Self::NotPerformed => transcript.push_u8(0),
            Self::Performed {
                engine,
                result_digest,
                input_digest,
            } => {
                transcript.push_u8(1);
                transcript.push_u8(*engine as u8);
                result_digest.encode(transcript)?;
                input_digest.encode(transcript)?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for BrowserOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ActivationNonce, BrowserContext, BrowserContextError, BrowserFamily, BrowserOrigin,
        BrowserProvenance, ChannelNonce, DocumentId, DocumentLifecycle, ExtensionId,
        ProfileInstallId, RequestId, SessionId,
    };

    #[test]
    fn origin_is_an_origin_not_a_url() {
        assert!(BrowserOrigin::new("https://example.test").is_ok());
        assert!(BrowserOrigin::new("http://localhost:8545").is_ok());
        assert_eq!(
            BrowserOrigin::new("https://example.test/path"),
            Err(BrowserContextError::InvalidOrigin)
        );
        assert_eq!(
            BrowserOrigin::new("https://user@example.test"),
            Err(BrowserContextError::InvalidOrigin)
        );
        assert_eq!(
            BrowserOrigin::new("https://EXAMPLE.test"),
            Err(BrowserContextError::InvalidOrigin)
        );
        assert_eq!(
            BrowserOrigin::new("https://example.test:99999"),
            Err(BrowserContextError::InvalidOrigin)
        );
    }

    fn valid_context() -> Result<BrowserContext, BrowserContextError> {
        Ok(BrowserContext {
            browser_family: BrowserFamily::Chrome,
            profile_install_id: ProfileInstallId::new([1; 32]),
            extension_id: ExtensionId::new("abcdefghijklmnopabcdefghijklmnop")?,
            tab_id: 1,
            frame_id: 0,
            document_id: DocumentId::new("secret-document-marker")?,
            activation_nonce: ActivationNonce::new([2; 32]),
            top_origin: BrowserOrigin::new("https://example.test")?,
            frame_origin: BrowserOrigin::new("https://example.test")?,
            document_lifecycle: DocumentLifecycle::Active,
            channel_nonce: ChannelNonce::new([3; 32]),
            provenance: BrowserProvenance::BrowserReportedUnverified,
            session_id: SessionId::new([4; 32]),
            sequence: 1,
            deadline_ms: 2,
            request_id: RequestId::new([5; 16]),
        })
    }

    #[test]
    fn browser_context_debug_redacts_origins_and_identifiers() -> Result<(), BrowserContextError> {
        let context = valid_context()?;
        let rendered = format!("{context:?}");
        assert!(rendered.contains("BrowserContext"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("example.test"));
        assert!(!rendered.contains("secret-document-marker"));
        assert!(!rendered.contains("abcdefghijklmnop"));
        assert!(!rendered.contains("1, 1, 1"));
        assert!(!rendered.contains("5, 5, 5"));
        Ok(())
    }

    #[test]
    fn version_one_signing_context_is_top_level_active_https() -> Result<(), BrowserContextError> {
        let context = valid_context()?;
        assert_eq!(context.validate(), Ok(()));

        let mut subframe = context.clone();
        subframe.frame_id = 1;
        assert_eq!(
            subframe.validate(),
            Err(BrowserContextError::UnsupportedSigningContext)
        );

        let mut cached = context.clone();
        cached.document_lifecycle = DocumentLifecycle::Cached;
        assert_eq!(
            cached.validate(),
            Err(BrowserContextError::UnsupportedSigningContext)
        );

        let mut zero_activation = context;
        zero_activation.activation_nonce = ActivationNonce::new([0; 32]);
        assert_eq!(
            zero_activation.validate(),
            Err(BrowserContextError::UnsupportedSigningContext)
        );
        Ok(())
    }
}
