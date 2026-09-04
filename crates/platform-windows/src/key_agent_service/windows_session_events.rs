//! Dormant typed boundary for Windows session-change notifications.
//!
//! The boundary validates an owned native notification before constructing a
//! lifecycle event. It deliberately has no executable caller or operating-
//! system registration path; a later integration phase must supply that edge.

use core::fmt;
use core::mem::size_of;

use thiserror::Error;
use windows::Win32::System::RemoteDesktop::WTSSESSION_NOTIFICATION;
use windows::Win32::UI::WindowsAndMessaging::{
    WTS_CONSOLE_CONNECT, WTS_CONSOLE_DISCONNECT, WTS_REMOTE_CONNECT, WTS_REMOTE_DISCONNECT,
    WTS_SESSION_CREATE, WTS_SESSION_LOCK, WTS_SESSION_LOGOFF, WTS_SESSION_LOGON,
    WTS_SESSION_REMOTE_CONTROL, WTS_SESSION_TERMINATE, WTS_SESSION_UNLOCK,
};

use super::lifecycle_core::{LifecycleError, SessionEvent, SessionId, SessionInvalidationReport};
use super::windows_lifecycle::WindowsNoSecretService;

/// A rejected native notification or runtime-policy dispatch.
///
/// The failure intentionally stores no native notification, event code, or
/// session identifier and is neither cloneable nor copyable. Its debug
/// representation exposes only the failure class.
#[derive(Error)]
pub(super) enum WindowsSessionChangeFailure {
    #[error("the Windows session notification size is invalid")]
    InvalidNotificationSize,
    #[error("the Windows session identifier is invalid")]
    InvalidSessionIdentifier,
    #[error("the Windows session event type is unsupported")]
    UnsupportedEventType,
    #[error("the runtime policy rejected a validated Windows session event")]
    RuntimePolicy(#[source] LifecycleError),
}

impl fmt::Debug for WindowsSessionChangeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNotificationSize => formatter
                .write_str("WindowsSessionChangeFailure::InvalidNotificationSize([REDACTED])"),
            Self::InvalidSessionIdentifier => formatter
                .write_str("WindowsSessionChangeFailure::InvalidSessionIdentifier([REDACTED])"),
            Self::UnsupportedEventType => {
                formatter.write_str("WindowsSessionChangeFailure::UnsupportedEventType([REDACTED])")
            }
            Self::RuntimePolicy(_) => {
                formatter.write_str("WindowsSessionChangeFailure::RuntimePolicy([REDACTED])")
            }
        }
    }
}

/// A size-checked, nonzero-session lifecycle event.
///
/// This carrier is deliberately move-only so one validated notification has
/// one dispatch opportunity.
#[must_use = "a validated session event must be dispatched or explicitly discarded"]
struct ValidatedWindowsSessionEvent {
    event: SessionEvent,
}

impl ValidatedWindowsSessionEvent {
    /// Validates the exact native layout marker and converts a supported event.
    fn decode(
        event_type: u32,
        notification: WTSSESSION_NOTIFICATION,
    ) -> Result<Self, WindowsSessionChangeFailure> {
        let Ok(expected_size) = u32::try_from(size_of::<WTSSESSION_NOTIFICATION>()) else {
            return Err(WindowsSessionChangeFailure::InvalidNotificationSize);
        };
        if notification.cbSize != expected_size {
            return Err(WindowsSessionChangeFailure::InvalidNotificationSize);
        }

        let session = SessionId::new(notification.dwSessionId)
            .map_err(|_| WindowsSessionChangeFailure::InvalidSessionIdentifier)?;

        if matches!(event_type, WTS_SESSION_CREATE | WTS_SESSION_TERMINATE) {
            return Err(WindowsSessionChangeFailure::UnsupportedEventType);
        }

        let event = match event_type {
            WTS_SESSION_LOCK => SessionEvent::Lock(session),
            WTS_SESSION_UNLOCK => SessionEvent::Unlock(session),
            WTS_SESSION_LOGOFF => SessionEvent::Logoff(session),
            WTS_CONSOLE_CONNECT
            | WTS_CONSOLE_DISCONNECT
            | WTS_REMOTE_CONNECT
            | WTS_REMOTE_DISCONNECT
            | WTS_SESSION_LOGON
            | WTS_SESSION_REMOTE_CONTROL => SessionEvent::UserSwitch(session),
            _ => return Err(WindowsSessionChangeFailure::UnsupportedEventType),
        };

        Ok(Self { event })
    }

    /// Dispatches through the sole Windows no-secret runtime facade.
    fn dispatch(
        self,
        service: &mut WindowsNoSecretService<'_>,
    ) -> Result<SessionInvalidationReport, WindowsSessionChangeFailure> {
        match service.handle_session_event(self.event) {
            Ok(report) => Ok(report),
            Err(cause) => Err(WindowsSessionChangeFailure::RuntimePolicy(cause)),
        }
    }
}

impl fmt::Debug for ValidatedWindowsSessionEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidatedWindowsSessionEvent([REDACTED])")
    }
}

/// Validates and dispatches one owned Windows session-change notification.
pub(super) fn handle_windows_session_change(
    service: &mut WindowsNoSecretService<'_>,
    event_type: u32,
    notification: WTSSESSION_NOTIFICATION,
) -> Result<SessionInvalidationReport, WindowsSessionChangeFailure> {
    ValidatedWindowsSessionEvent::decode(event_type, notification)?.dispatch(service)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use core::mem::{offset_of, size_of};

    use super::*;

    trait AmbiguousIfClone<Marker> {
        fn marker() {}
    }
    impl<T> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}

    trait AmbiguousIfCopy<Marker> {
        fn marker() {}
    }
    impl<T> AmbiguousIfCopy<()> for T {}
    impl<T: Copy> AmbiguousIfCopy<u8> for T {}

    macro_rules! assert_move_only {
        ($type:ty) => {
            let _ = <$type as AmbiguousIfClone<_>>::marker;
            let _ = <$type as AmbiguousIfCopy<_>>::marker;
        };
    }

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn native_size() -> u32 {
        u32::try_from(size_of::<WTSSESSION_NOTIFICATION>()).unwrap_or(u32::MAX)
    }

    fn notification(size: u32, session: u32) -> WTSSESSION_NOTIFICATION {
        WTSSESSION_NOTIFICATION {
            cbSize: size,
            dwSessionId: session,
        }
    }

    fn decoded(
        event_type: u32,
        session: u32,
    ) -> Result<ValidatedWindowsSessionEvent, WindowsSessionChangeFailure> {
        ValidatedWindowsSessionEvent::decode(event_type, notification(native_size(), session))
    }

    #[test]
    fn native_session_notification_layout_is_exact() {
        assert_eq!(size_of::<WTSSESSION_NOTIFICATION>(), 2 * size_of::<u32>());
        assert_eq!(offset_of!(WTSSESSION_NOTIFICATION, cbSize), 0);
        assert_eq!(
            offset_of!(WTSSESSION_NOTIFICATION, dwSessionId),
            size_of::<u32>()
        );
    }

    #[test]
    fn notification_size_must_match_exactly() {
        let expected = native_size();
        for size in [expected.saturating_sub(1), expected.saturating_add(1)] {
            assert!(matches!(
                ValidatedWindowsSessionEvent::decode(WTS_SESSION_LOCK, notification(size, 41)),
                Err(WindowsSessionChangeFailure::InvalidNotificationSize)
            ));
        }
        assert!(matches!(
            ValidatedWindowsSessionEvent::decode(
                u32::MAX,
                notification(expected.saturating_sub(1), 0),
            ),
            Err(WindowsSessionChangeFailure::InvalidNotificationSize)
        ));
        assert!(
            ValidatedWindowsSessionEvent::decode(WTS_SESSION_LOCK, notification(expected, 41))
                .is_ok()
        );
    }

    #[test]
    fn zero_session_identifier_is_rejected_before_event_mapping() {
        assert!(matches!(
            ValidatedWindowsSessionEvent::decode(u32::MAX, notification(native_size(), 0)),
            Err(WindowsSessionChangeFailure::InvalidSessionIdentifier)
        ));
    }

    #[test]
    fn lock_and_unlock_map_to_exact_session_events() -> TestResult {
        let expected = SessionId::new(43)?;
        assert!(matches!(
            decoded(WTS_SESSION_LOCK, 43)?.event,
            SessionEvent::Lock(session) if session == expected
        ));
        assert!(matches!(
            decoded(WTS_SESSION_UNLOCK, 43)?.event,
            SessionEvent::Unlock(session) if session == expected
        ));
        Ok(())
    }

    #[test]
    fn logoff_maps_to_exact_session_event() -> TestResult {
        let expected = SessionId::new(47)?;
        assert!(matches!(
            decoded(WTS_SESSION_LOGOFF, 47)?.event,
            SessionEvent::Logoff(session) if session == expected
        ));
        Ok(())
    }

    #[test]
    fn connect_disconnect_logon_and_remote_control_map_to_user_switch() -> TestResult {
        let expected = SessionId::new(53)?;
        for event_type in [
            WTS_CONSOLE_CONNECT,
            WTS_CONSOLE_DISCONNECT,
            WTS_REMOTE_CONNECT,
            WTS_REMOTE_DISCONNECT,
            WTS_SESSION_LOGON,
            WTS_SESSION_REMOTE_CONTROL,
        ] {
            assert!(matches!(
                decoded(event_type, 53)?.event,
                SessionEvent::UserSwitch(session) if session == expected
            ));
        }
        Ok(())
    }

    #[test]
    fn reserved_and_unknown_event_types_are_rejected() {
        for event_type in [0, WTS_SESSION_CREATE, WTS_SESSION_TERMINATE, u32::MAX] {
            assert!(matches!(
                ValidatedWindowsSessionEvent::decode(event_type, notification(native_size(), 59)),
                Err(WindowsSessionChangeFailure::UnsupportedEventType)
            ));
        }
    }

    #[test]
    fn validated_event_is_move_only_redacted_and_dispatches_only_through_runtime_facade()
    -> TestResult {
        assert_move_only!(ValidatedWindowsSessionEvent);
        assert_move_only!(WindowsSessionChangeFailure);

        let event = decoded(WTS_SESSION_LOCK, 61)?;
        assert_eq!(
            format!("{event:?}"),
            "ValidatedWindowsSessionEvent([REDACTED])"
        );
        let failure = WindowsSessionChangeFailure::InvalidSessionIdentifier;
        assert_eq!(
            format!("{failure:?}"),
            "WindowsSessionChangeFailure::InvalidSessionIdentifier([REDACTED])"
        );
        let runtime_failure = WindowsSessionChangeFailure::RuntimePolicy(LifecycleError::Fatal);
        assert_eq!(
            format!("{runtime_failure:?}"),
            "WindowsSessionChangeFailure::RuntimePolicy([REDACTED])"
        );
        assert!(runtime_failure.source().is_some());

        let _: for<'provider> fn(
            ValidatedWindowsSessionEvent,
            &mut WindowsNoSecretService<'provider>,
        )
            -> Result<SessionInvalidationReport, WindowsSessionChangeFailure> =
            ValidatedWindowsSessionEvent::dispatch;
        let _: for<'provider> fn(
            &mut WindowsNoSecretService<'provider>,
            u32,
            WTSSESSION_NOTIFICATION,
        )
            -> Result<SessionInvalidationReport, WindowsSessionChangeFailure> =
            handle_windows_session_change;

        let production = include_str!("windows_session_events.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .collect::<String>();
        assert_eq!(
            production.matches("service.handle_session_event(").count(),
            1
        );
        assert!(production.contains("service.handle_session_event(self.event)"));
        assert!(!production.contains("service.policy"));
        Ok(())
    }
}
