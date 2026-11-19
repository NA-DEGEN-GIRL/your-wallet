//! The headless approval host (2026-11-20, S4 B7; spec/15 §11.4 S4, spec/09 §2.1): `cfg(test)`
//! only, release builds compile none of it.
//!
//! While it is installed on the test thread, `App::apply_approval_effect` (the executor arm of
//! `Effect::Approval`) records each approval effect instead of applying it, and answers an open
//! itself: no approval window, panel or AI body is made, nothing is shown, laid out or painted,
//! and `App.approval_win` stays `None`. The open is answered as the hidden A01 of the windowed
//! harness answers it (`OpenOutcome::Shown { capture_excluded: false }` with the width class of
//! the 820 DIP window, wide), or `Failed(E-APP-009)` when the test asks for a refused window (the
//! open-failure path) or when `shown` is no longer the current flow's (critique A-3, as
//! `open_approval_window` does). The flow half runs unchanged: this is the "shell half absent"
//! run of the approval flow and lifecycle scenarios, `app_approval::flow_tests::lifecycle::
//! headless` (gate test step, no `#[ignore]`).
//!
//! The windowed harness (`TEST_APPROVAL_HOST` of `flow_support`, gate step `winui`) stays: real
//! Win32 re-entrancy and window traces (`s4_flow/input.txt`, `reentry.txt`, the `l1_*` traces,
//! focus, Tab and panel clicks, `windows=N`) cannot come from a run without windows (plan
//! critique A-7/A-8).

use std::cell::RefCell;

use yw_engine::approval::flow::{ApprovalEffect, OpenOutcome, ShownId};
use yw_engine::cmd::Cmd;

use crate::errors::ErrorCode;

/// How the headless host answers an open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenAnswer {
    /// As the hidden A01 of the windowed harness: shown, not capture-excluded, wide.
    Shown,
    /// As a window that cannot be made: `Failed(E-APP-009)` (`HostMode::FailOpen` of the windowed
    /// harness).
    Failed,
}

/// The width class a hidden A01 of 820 DIP reports (`ApprovalWin::is_wide`: at least 80 average
/// characters of 8 DIP).
const WIDE: bool = true;

struct Host {
    answer: OpenAnswer,
    effects: Vec<ApprovalEffect>,
}

thread_local! {
    static HOST: RefCell<Option<Host>> = const { RefCell::new(None) };
}

/// Installs the headless host on this thread (a fresh effect record).
pub(crate) fn install(answer: OpenAnswer) {
    let _ = HOST.try_with(|slot| {
        *slot.borrow_mut() = Some(Host {
            answer,
            effects: Vec::new(),
        });
    });
}

/// Removes it (the approval effects are applied again).
pub(crate) fn remove() {
    let _ = HOST.try_with(|slot| *slot.borrow_mut() = None);
}

/// Whether the headless host is installed on this thread.
pub(crate) fn installed() -> bool {
    HOST.try_with(|slot| slot.borrow().is_some())
        .unwrap_or(false)
}

/// The approval effects recorded since the last call, in emission order.
pub(crate) fn take_effects() -> Vec<ApprovalEffect> {
    HOST.try_with(|slot| {
        slot.borrow_mut()
            .as_mut()
            .map(|host| std::mem::take(&mut host.effects))
    })
    .ok()
    .flatten()
    .unwrap_or_default()
}

/// Records `effect` (the host must be installed) instead of applying it and returns the
/// executor's answer: `Cmd::ApprovalOpened` for an open (`current`: the shown flow's id), `None`
/// for the others.
pub(crate) fn record(effect: ApprovalEffect, current: Option<ShownId>) -> Option<Cmd> {
    HOST.try_with(|slot| {
        let mut slot = slot.borrow_mut();
        let host = slot.as_mut()?;
        host.effects.push(effect);
        match effect {
            ApprovalEffect::Open { shown, .. } => {
                let made = host.answer == OpenAnswer::Shown && current == Some(shown);
                Some(Cmd::ApprovalOpened {
                    shown,
                    outcome: if made {
                        OpenOutcome::Shown {
                            capture_excluded: false,
                        }
                    } else {
                        OpenOutcome::Failed(ErrorCode::App009)
                    },
                    wide: made && WIDE,
                })
            }
            ApprovalEffect::Close { .. }
            | ApprovalEffect::Rebuilt { .. }
            | ApprovalEffect::RepaintBar { .. }
            | ApprovalEffect::Redraw { .. } => None,
        }
    })
    .ok()
    .flatten()
}
