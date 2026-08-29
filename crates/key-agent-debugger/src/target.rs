//! Exact inert target mode for the dormant topology fixture.

use std::ffi::{OsStr, OsString};

pub(super) const TARGET_MODE_ARG: &str = "--yw-dormant-target-topology-fixture";

pub(super) fn is_exact_invocation(mut args: impl Iterator<Item = OsString>) -> bool {
    args.next()
        .is_some_and(|argument| argument == OsStr::new(TARGET_MODE_ARG))
        && args.next().is_none()
}

/// Remains inert even if a faulty fixture resumes the primary thread.
pub(super) fn run() -> ! {
    loop {
        std::thread::park();
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{TARGET_MODE_ARG, is_exact_invocation};

    #[test]
    fn only_the_single_fixed_argument_selects_target_mode() {
        assert!(is_exact_invocation(
            [OsString::from(TARGET_MODE_ARG)].into_iter()
        ));
        assert!(!is_exact_invocation([].into_iter()));
        assert!(!is_exact_invocation(
            [OsString::from("--different")].into_iter()
        ));
        assert!(!is_exact_invocation(
            [
                OsString::from(TARGET_MODE_ARG),
                OsString::from("unexpected"),
            ]
            .into_iter()
        ));
    }
}
