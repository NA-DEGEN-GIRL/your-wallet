//! The shown approval's flow state (spec/04 §3, spec/03 §11.5, spec/15 §11.4 S4): the request
//! the window shows, its preparation, the issued approval and the gate with its interaction
//! (`ApprovalSession`). 2026-11-19 (S4 B4a, plan D-7): split out of the yw-app `ApprovalUi` of
//! `app_approval.rs` unchanged. 2026-11-19 (S4 B4b): the rest of `ApprovalUi` is the shell state
//! `app_approval::ApprovalWin` (window, panel, AI body and its scroll, focus, scroll, pressed
//! button, layout, bottom bar, glyph widths); the AI panel's state is here ([`AiFlow`]), beside the
//! session, never inside it; the window paints from the read model [`ApprovalPaint`].
//!
//! Every field is private: the methods below are the only writers of the gate, and each keeps
//! the order of the code it came from (the deadline before `replace_content`, `connect_selected`
//! after it, `submitting` before any dispatch). `issued` is the one handle `consume` and `reject`
//! use. The module names no window type: it moves to yw-engine with the flow at S4d (source check
//! S3 in `app_approval_input_tests.rs`). Not the send flows of `yw_engine::flow`.
//!
//! 2026-11-19 (S4 B5): every flow carries the [`ShownId`] of its window, allocated when it opens,
//! and the width class the shell reported (`Cmd::ApprovalOpened`, then each A01 `WM_SIZE` /
//! `WM_DPICHANGED`); the window's operations are `Effect::Approval`s the App emits (open, close,
//! rebuilt view, bottom bar). The flow is made before its window is asked for and gets its AI
//! explanation when the window was made ([`ApprovalFlow::attach_ai`]). 2026-11-19 (S4 B5 review):
//! whether the window has an AI explanation is decided once, when the flow opens ([`AiReserved`]:
//! the request kind and the endpoint's host and model of that moment); the answer attaches what
//! was reserved and never asks again (before, it worked the condition out a second time).
//!
//! 2026-11-19 (S4 B6, plan §3.1, critique A-12, A-13): the window's inputs reach the flow as
//! `Cmd::Approval` (`Wallet::on_approval_input`), dropped unless their `ShownId` is this flow's
//! ([`ApprovalFlow::shown`]). Every new view bumps [`ApprovalFlow::view_rev`]; the shell keeps
//! the revision its panel layout was drawn from, and a connect account toggle drawn from an
//! older view changes nothing ([`ApprovalFlow::toggle_account`]).

use yw_core::approval::{ApprovalRequest, RiskLevel};
use yw_core::evm::eip712::DecodedTypedData;
use yw_core::lang::Lang;
use yw_engine::approval::flow::{
    BarFacts, BarSource, ShownId, StatusAction, bar_facts, is_release, session_deadline,
    status_action,
};
use yw_engine::approval::interaction::{
    ApprovalGate, ApprovalSession, ConnectView, InteractionError, InteractionEvent,
    InteractionStatus, PrepareStage, PrepareState, ReadyContent,
};
use yw_engine::approval::text;
use yw_engine::approval::view::{ApprovalView, Block};
use yw_engine::errors::ErrorCode;
use yw_engine::explain::input::RequestKind;
use yw_engine::explain::panel::{AiPanel, held_for_ack};
use yw_engine::flow::evm::prepare::{Prepared, ResimKind};

use crate::app_approval::ConnectState;
use crate::app_evm::QueuedItem;

/// The shown approval's flow: today's `ApprovalUi` minus the window, the panel, the AI body and
/// the paint state (spec/15 §11.4 S4, plan §3.1).
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent window facts of the flow (early release, raw fold, re-simulation click, width class)"
)]
pub struct ApprovalFlow {
    /// The window this flow is shown in: a fresh serial at every open, never reused (2026-11-19,
    /// S4 B5). The queue item id stays the idle identity.
    shown: ShownId,
    /// The window's language: the app language when it opened. The request is built in it, so
    /// the display (digested with its language, spec/03 §11.3) and the chrome always match.
    lang: Lang,
    item: QueuedItem,
    connect: Option<ConnectState>,
    typed: Option<Box<DecodedTypedData>>,
    /// The gate and its interaction; never handed out as `&mut`.
    session: ApprovalSession,
    job: u64,
    prepared: Option<Box<Prepared>>,
    /// The issued approval (spec/03 §11.5): the handle `consume` and `reject` use (was
    /// `ApprovalUi.request`).
    issued: Option<ApprovalRequest>,
    failure: Option<String>,
    status: Option<String>,
    /// A high-risk hold was let go before 2 s (the status line says so until the next press).
    early_release: bool,
    raw_open: bool,
    resim_click: bool,
    view: ApprovalView,
    /// The revision of `view`: bumped by every new view (2026-11-19, S4 B6, critique A-13), so a
    /// connect toggle hit-tested on a layout drawn from an older view can be told apart.
    view_rev: u64,
    /// The wide layout applies (the A01 client area is at least 640 DIP wide): reported by the
    /// shell when the window opens and at each A01 size or DPI change (2026-11-19, S4 B5: was read
    /// from the window by every view rebuild).
    wide: bool,
    /// The AI explanation reserved when the flow opened, until the open's answer attaches it
    /// (2026-11-19, S4 B5 review).
    ai_reserved: Option<AiReserved>,
    /// The AI explanation (spec/06 §6), when the window reserved its panel (2026-11-19, S4 B4b:
    /// was the state half of `app_approval::AiUi`).
    ai: Option<AiFlow>,
}

/// The AI explanation reserved for a flow when it opens (spec/06 §3.1: a request kind that has
/// one, while the explanation worker exists): the request kind and the endpoint's host and model
/// of that moment. The open asks for the AI body iff one is reserved, and the open's answer turns
/// it into the [`AiFlow`] (2026-11-19, S4 B5 review: decided once, not again at the answer).
pub struct AiReserved {
    pub(crate) kind: RequestKind,
    pub(crate) host: String,
    pub(crate) model: String,
}

/// Names only (D28): never the host or the model.
impl core::fmt::Debug for AiReserved {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("AiReserved").finish_non_exhaustive()
    }
}

/// The AI explanation of the shown approval (spec/06 §6, spec/04 §3.8): the panel state, the
/// request serial of this window, the endpoint host and model, and the request kind. Beside the
/// session, never inside it: it holds no gate type and no method of it reads or writes the gate
/// (source check S3, D21). Its body window and the body's scroll are shell state
/// (`app_approval::ApprovalWin`). (2026-11-19, S4 B4b: was the state half of
/// `app_approval::AiUi`.)
pub struct AiFlow {
    pub(crate) panel: AiPanel,
    pub(crate) serial: u64,
    pub(crate) host: String,
    pub(crate) model: String,
    pub(crate) kind: RequestKind,
}

impl core::fmt::Debug for AiFlow {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AiFlow")
            .field("state", self.panel.state())
            .finish_non_exhaustive()
    }
}

/// What the approval window paints, read from the flow (2026-11-19, S4 B4b, plan D-19): no
/// `&mut`. While it paints, the session reaches the shell only as the bottom bar's facts
/// ([`Self::bar`]); the smoke harness and the tour hooks read through here too. It is not the
/// shell's only way to the flow (2026-11-19, S4 B4 review: this said "one reviewed read
/// surface", stronger than the code): before the AI body paints, `paint_ai_body` calls
/// [`ApprovalFlow::hold_ai_for_ack`] (2026-11-22, S4c W15: through the wallet's
/// `hold_shown_ai_for_ack`), which writes the AI panel's held flag (never the gate), and
/// the window's input steps and layout read the flow's read-only accessors (`Step::Tab` reads
/// [`ApprovalFlow::view`] for the tab order).
pub(crate) struct ApprovalPaint<'a> {
    /// The window's language.
    pub(crate) lang: Lang,
    /// The view drawn.
    pub(crate) view: &'a ApprovalView,
    /// The revision of `view` (the shell's layout keeps it; 2026-11-19, S4 B6, A-13).
    pub(crate) view_rev: u64,
    /// The status message.
    pub(crate) status: Option<&'a str>,
    /// The shown content (`Preparing`, `Ready`, `Failed`); read by the render harness only.
    #[cfg(test)]
    pub(crate) prepare: &'a PrepareState,
    /// The acknowledgement checkbox is checked.
    pub(crate) ack_checked: bool,
    /// The interaction's status; read by the render harness only (2026-11-19, S4 B4 review:
    /// `cfg(test)` like `prepare`, a release paint computed it for nothing).
    #[cfg(test)]
    pub(crate) interaction: InteractionStatus,
    /// A high-risk hold is under way; read by the render harness only (`cfg(test)`, as above).
    #[cfg(test)]
    pub(crate) holding: bool,
    /// The AI explanation, when the window has one.
    pub(crate) ai: Option<&'a AiFlow>,
    bar: BarSource<'a>,
}

impl ApprovalPaint<'_> {
    /// The bottom bar's facts at `now` (`yw_engine::approval::flow::bar_facts`, S4 B3).
    pub(crate) fn bar(&self, now: u64) -> BarFacts {
        bar_facts(&self.bar, now)
    }
}

/// Names and flags only (D28); the interaction status and the hold in test builds only.
impl core::fmt::Debug for ApprovalPaint<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut out = formatter.debug_struct("ApprovalPaint");
        out.field("lang", &self.lang)
            .field("ack_checked", &self.ack_checked);
        #[cfg(test)]
        out.field("interaction", &self.interaction)
            .field("holding", &self.holding);
        out.finish_non_exhaustive()
    }
}

/// Names only (D28): never the request, a text or an address.
impl core::fmt::Debug for ApprovalFlow {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ApprovalFlow")
            .field("shown", &self.shown)
            .field("job", &self.job)
            .field("issued", &self.issued.is_some())
            .finish_non_exhaustive()
    }
}

impl ApprovalFlow {
    /// The flow of window `shown` opening at `now`: the gate starts `Preparing(Building)`,
    /// unarmed, not foreground, with the deadline of `session_deadline` (the site deadline, else
    /// `now + MAX_LIFETIME_MS`; S4 B3). 2026-11-19 (S4 B5): made before the window is asked for
    /// (was after the window, its panel and AI body existed, with the AI explanation as an
    /// argument; the AI explanation is now [`Self::attach_ai`]). The layout is wide until the
    /// open's result reports the window's class. 2026-11-19 (S4 B5 review): `ai_reserved` is the
    /// AI explanation decided now, kept until the open's answer ([`Self::take_ai_reserved`]).
    ///
    /// # Errors
    ///
    /// [`InteractionError`] for an invalid deadline.
    pub(crate) fn open(
        shown: ShownId,
        lang: Lang,
        item: QueuedItem,
        connect: Option<ConnectState>,
        ai_reserved: Option<AiReserved>,
        now: u64,
    ) -> Result<Self, InteractionError> {
        let site_deadline = match &item {
            QueuedItem::Site(site) => Some(site.deadline_ms),
            QueuedItem::App(_)
            | QueuedItem::Sol(_)
            | QueuedItem::Btc(_)
            | QueuedItem::Zec(_)
            | QueuedItem::HyperCore(_) => None,
        };
        let gate = ApprovalGate {
            prepare: PrepareState::Preparing(PrepareStage::Building),
            ack_checked: false,
            connect_selected: 0,
            ready_at_ms: now,
            is_foreground: false,
            deadline_ms: session_deadline(site_deadline, now),
            submitting: false,
        };
        let session = ApprovalSession::new(gate, now)?;
        Ok(Self {
            shown,
            lang,
            item,
            connect,
            typed: None,
            session,
            job: 0,
            prepared: None,
            issued: None,
            failure: None,
            status: None,
            early_release: false,
            raw_open: false,
            resim_click: false,
            view: ApprovalView::default(),
            view_rev: 0,
            wide: true,
            ai_reserved,
            ai: None,
        })
    }

    // ----- reads ----------------------------------------------------------------------------

    /// The window this flow is shown in (S4 B5).
    pub(crate) const fn shown(&self) -> ShownId {
        self.shown
    }

    /// The wide layout applies (S4 B5: the class the shell reported).
    pub(crate) const fn wide(&self) -> bool {
        self.wide
    }

    /// The window's language.
    pub(crate) const fn lang(&self) -> Lang {
        self.lang
    }

    /// The queued item the window shows.
    pub(crate) const fn item(&self) -> &QueuedItem {
        &self.item
    }

    /// The connect window's accounts and chain.
    pub(crate) const fn connect(&self) -> Option<&ConnectState> {
        self.connect.as_ref()
    }

    /// The validated typed data of an `eth_signTypedData_v4` window.
    pub(crate) fn typed(&self) -> Option<&DecodedTypedData> {
        self.typed.as_deref()
    }

    /// The gate and its interaction (read-only; the tests' recorders. 2026-11-19, S4 B4b: the
    /// window reads the bar facts through `ApprovalPaint`).
    #[cfg(test)]
    pub(crate) const fn session(&self) -> &ApprovalSession {
        &self.session
    }

    /// The gate (read-only).
    pub(crate) const fn gate(&self) -> &ApprovalGate {
        &self.session.gate
    }

    /// The current preparation job id.
    pub(crate) const fn job(&self) -> u64 {
        self.job
    }

    /// The preparation of a transaction (signing, journal, re-simulation).
    pub(crate) fn prepared(&self) -> Option<&Prepared> {
        self.prepared.as_deref()
    }

    /// The issued approval: the handle `consume` and `reject` use.
    pub(crate) const fn issued(&self) -> Option<&ApprovalRequest> {
        self.issued.as_ref()
    }

    /// The failure text of a `Failed` window.
    pub(crate) fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }

    /// The status message (the tests' recorders; the window reads `ApprovalPaint::status`).
    #[cfg(test)]
    pub(crate) fn status(&self) -> Option<&str> {
        self.status.as_deref()
    }

    /// A high-risk hold was let go before 2 s (the tests' recorders; the window reads it as
    /// a bar fact).
    #[cfg(test)]
    pub(crate) const fn early_release(&self) -> bool {
        self.early_release
    }

    /// The raw data is unfolded.
    pub(crate) const fn raw_open(&self) -> bool {
        self.raw_open
    }

    /// The running re-simulation was asked for by an approving click.
    pub(crate) const fn resim_click(&self) -> bool {
        self.resim_click
    }

    /// The view drawn.
    pub(crate) const fn view(&self) -> &ApprovalView {
        &self.view
    }

    /// The revision of the view drawn (2026-11-19, S4 B6, A-13; the tests' read, the window
    /// reads it through `ApprovalPaint`).
    #[cfg(test)]
    pub(crate) const fn view_rev(&self) -> u64 {
        self.view_rev
    }

    /// What the window paints (2026-11-19, S4 B4b).
    pub(crate) fn paint(&self) -> ApprovalPaint<'_> {
        ApprovalPaint {
            lang: self.lang,
            view: &self.view,
            view_rev: self.view_rev,
            status: self.status.as_deref(),
            #[cfg(test)]
            prepare: &self.session.gate.prepare,
            ack_checked: self.session.gate.ack_checked,
            #[cfg(test)]
            interaction: self.session.interaction().status(),
            #[cfg(test)]
            holding: self.session.interaction().hold_source().is_some(),
            ai: self.ai.as_ref(),
            bar: BarSource {
                lang: self.lang,
                session: &self.session,
                view: &self.view,
                connect: self.connect.is_some(),
                early_release: self.early_release,
                status: self.status.as_deref(),
            },
        }
    }

    // ----- AI explanation (spec/06), beside the gate ----------------------------------------

    /// The AI explanation, when the window has one.
    pub(crate) const fn ai(&self) -> Option<&AiFlow> {
        self.ai.as_ref()
    }

    /// The AI explanation to update (its panel state only: it holds no gate).
    pub(crate) fn ai_mut(&mut self) -> Option<&mut AiFlow> {
        self.ai.as_mut()
    }

    /// The AI explanation, taken when the window closes (spec/06 §3.2: a later result is
    /// dropped).
    pub(crate) fn take_ai(&mut self) -> Option<AiFlow> {
        self.ai.take()
    }

    /// The AI explanation of a window that was made with its AI body (2026-11-19, S4 B5: was an
    /// argument of [`Self::open`]).
    pub(crate) fn attach_ai(&mut self, ai: AiFlow) {
        self.ai = Some(ai);
    }

    /// The AI explanation reserved when the flow opened, taken by the open's answer (2026-11-19,
    /// S4 B5 review).
    pub(crate) fn take_ai_reserved(&mut self) -> Option<AiReserved> {
        self.ai_reserved.take()
    }

    /// A High-risk request shows its warnings first: the AI text waits for the acknowledgement
    /// checkbox (`held_for_ack`; read from the issued request and the gate, written to the AI
    /// panel only). Returns whether the window has an AI explanation.
    pub(crate) fn hold_ai_for_ack(&mut self) -> bool {
        let risk = self.issued.as_ref().map(|request| request.display.risk);
        let checked = self.session.gate.ack_checked;
        let Some(ai) = self.ai.as_mut() else {
            return false;
        };
        ai.panel.set_held(held_for_ack(risk, checked));
        true
    }

    // ----- preparation ----------------------------------------------------------------------

    /// A (new) preparation job starts: no failure, `Preparing(Building)` (a display change: hold,
    /// checkbox and arm delay reset).
    pub(crate) fn begin_prepare(&mut self, job: u64, now: u64) {
        self.job = job;
        self.failure = None;
        let _ = self
            .session
            .replace_content(now, PrepareState::Preparing(PrepareStage::Building));
    }

    /// `eth_simulateV1` started.
    pub(crate) fn simulating(&mut self, since_ms: u64, now: u64) {
        let _ = self.session.replace_content(
            now,
            PrepareState::Preparing(PrepareStage::Simulating { since_ms }),
        );
    }

    /// The connect window is ready: the queue's deadline first, then the content, then the
    /// selection count (`replace_content` keeps the count; it is set after it, as before).
    pub(crate) fn connect_ready(&mut self, deadline: u64, now: u64) {
        let selected = self.connect.as_ref().map_or(0, ConnectState::gate_count);
        let accounts = self
            .connect
            .as_ref()
            .map_or(0, |connect| connect.accounts.len());
        self.session.gate.deadline_ms = deadline;
        let _ = self.session.replace_content(
            now,
            PrepareState::Ready(ReadyContent::Connect(ConnectView { accounts })),
        );
        self.session.gate.connect_selected = selected;
    }

    /// The validated typed data of the shown typed-data request.
    pub(crate) fn set_typed(&mut self, typed: Box<DecodedTypedData>) {
        self.typed = Some(typed);
    }

    /// The window shows a failure (`Failed`, only `거부` and maybe `다시 시도`).
    pub(crate) fn fail(&mut self, text: String, code: ErrorCode, retryable: bool, now: u64) {
        self.failure = Some(text);
        let _ = self
            .session
            .replace_content(now, PrepareState::Failed { code, retryable });
    }

    /// The first Ready display of an issued request (spec/03 §11.5): the raw data unfolded for
    /// High and above, the queue's deadline, then the content, then the issued request and its
    /// preparation.
    pub(crate) fn show_ready(
        &mut self,
        request: ApprovalRequest,
        prepared: Option<Box<Prepared>>,
        deadline: u64,
        now: u64,
    ) {
        self.raw_open = request.display.risk >= RiskLevel::High;
        self.session.gate.deadline_ms = deadline;
        let _ = self.session.replace_content(
            now,
            PrepareState::Ready(ReadyContent::Signing(Box::new(request.clone()))),
        );
        self.issued = Some(request);
        self.prepared = prepared;
    }

    /// The view the window draws: a new revision (2026-11-19, S4 B6, A-13; every caller then
    /// emits `Rebuilt { changed: true }`, which drops the shell's layout).
    pub(crate) fn set_view(&mut self, view: ApprovalView) {
        self.view = view;
        self.view_rev = self.view_rev.wrapping_add(1);
    }

    /// The width class the shell reported (the open's result, an A01 size or DPI change; S4
    /// B5). The next view rebuild lays out for it.
    pub(crate) fn set_wide(&mut self, wide: bool) {
        self.wide = wide;
    }

    /// An open EVM connect window shows the origin's chain of now (security review L4(c)).
    /// Returns whether it changed.
    pub(crate) fn set_connect_chain(&mut self, chain_id: u64, name: String) -> bool {
        let Some(connect) = self.connect.as_mut() else {
            return false;
        };
        if connect.chain_id == chain_id {
            return false;
        }
        connect.chain_id = chain_id;
        connect.chain_name = name;
        true
    }

    // ----- interaction ----------------------------------------------------------------------

    /// One interaction event: the foreground sample first (a `false` → `true` edge restarts the
    /// arm delay), then the event, then the early-release note, then what it did
    /// (`status_action`, S4 B3). The order of today's `interaction()` in `app_approval.rs`
    /// (2026-11-19, S4 B6: `Wallet::approval_event`, with the sample `window_event` took).
    /// Pinned by `tests::the_foreground_sample_comes_before_the_event` and the source check S8
    /// (2026-11-19, S4 B4 review: no golden can show this order, the harness keeps the
    /// foreground steady between events).
    pub(crate) fn on_event(
        &mut self,
        now: u64,
        foreground: bool,
        event: InteractionEvent,
    ) -> StatusAction {
        self.session.set_foreground(now, foreground);
        let before = self.session.interaction().status();
        let holding = self.session.interaction().hold_remaining_ms(now).is_some();
        let status = self.session.event(now, event);
        if event.is_press() {
            self.early_release = false;
        } else if holding && status == InteractionStatus::Pending && is_release(event) {
            self.early_release = true;
        }
        let deadline = self.session.gate.deadline_ms;
        status_action(before, status, now, deadline)
    }

    /// The window came to the front (`WM_ACTIVATEAPP(true)`): the arm delay restarts
    /// unconditionally, then the gate is foreground.
    pub(crate) fn activated(&mut self, now: u64) {
        self.session.restart_arm_delay(now);
        self.session.set_foreground(now, true);
    }

    /// Toggles the acknowledgement checkbox when the view has one; returns whether it did.
    pub(crate) fn toggle_ack(&mut self, now: u64) -> bool {
        if !self.view.blocks.contains(&Block::Ack) {
            return false;
        }
        let checked = !self.session.gate.ack_checked;
        self.session.set_ack(now, checked);
        true
    }

    /// Toggles connect entry `index` (when it exists) of the list drawn at `view_rev`: the gate's
    /// selection count follows and the checkbox is cleared. Returns `false`, and changes nothing,
    /// for a toggle drawn from an older view than the one shown (2026-11-19, S4 B6, critique
    /// A-13: the index is a position in the list as it was drawn; before, any index was applied
    /// to the list of now). On Windows the panel layout is dropped with every new view, so a
    /// layout the shell hit-tests is always the shown view's and this never drops a click.
    pub(crate) fn toggle_account(&mut self, index: usize, view_rev: u64, now: u64) -> bool {
        if view_rev != self.view_rev {
            return false;
        }
        if let Some(connect) = self.connect.as_mut()
            && index < connect.selected.len()
        {
            connect.toggle(index);
            self.session.gate.connect_selected = connect.gate_count();
            self.session.set_ack(now, false);
        }
        true
    }

    /// Unfolds or folds the raw data.
    pub(crate) const fn toggle_raw(&mut self) {
        self.raw_open = !self.raw_open;
    }

    /// L4(c): the chain changed since the connect window was drawn. A fresh interaction first,
    /// then the arm delay (S4 F2, owner decision O-5): the redrawn chain needs a new armed click.
    pub(crate) fn chain_changed_at_approve(&mut self, now: u64) {
        let _ = self.session.restart_interaction(now);
        self.session.restart_arm_delay(now);
    }

    // ----- approve, re-simulation -----------------------------------------------------------

    /// A submission (re-simulation or consume) is in flight (C1).
    pub(crate) const fn submitting(&self) -> bool {
        self.session.gate.submitting
    }

    /// C1: one approval is acted on once. Set before the request is dispatched; the result
    /// replaces or resets the content.
    pub(crate) const fn begin_submit(&mut self) {
        self.session.gate.submitting = true;
    }

    /// The approval is being checked (`확인 중`) before its re-simulation decision.
    pub(crate) fn checking(&mut self) {
        self.status = Some(text::CHECKING.get(self.lang).to_owned());
    }

    /// A re-simulation job `job` is asked for (by an approving click when `click`).
    pub(crate) fn resim_requested(&mut self, job: u64, click: bool) {
        self.job = job;
        self.resim_click = click;
        self.session.gate.submitting = true;
        self.status = Some(text::SIMULATING_START.get(self.lang).to_owned());
    }

    /// C1: the approval that asked for the re-simulation has been acted on; the terminal
    /// `Approved` status must not dispatch it again on the next tick.
    pub(crate) fn resim_sent(&mut self, now: u64) {
        let _ = self.session.restart_interaction(now);
    }

    /// The re-simulation could not be sent: RPC-001, same content but a new approval.
    pub(crate) fn resim_not_sent(&mut self, now: u64) {
        self.status = Some(ErrorCode::Rpc001.text_in(self.lang));
        self.resim_click = false;
        let prepare = self.session.gate.prepare.clone();
        let _ = self.session.replace_content(now, prepare);
    }

    /// The re-simulation found a blocking failure: no status, no click (the failure follows).
    pub(crate) fn resim_failed(&mut self) {
        self.status = None;
        self.resim_click = false;
    }

    /// The re-simulation got no result: same content, but a new approval (checkbox, arm delay,
    /// fresh interaction).
    pub(crate) fn resim_no_result(&mut self, now: u64) {
        self.status = Some(format!(
            "{}{}",
            text::SIM_RESIM_FAILED.get(self.lang),
            text::SIM_RESIM_FAILED_STEP.get(self.lang)
        ));
        self.resim_click = false;
        let prepare = self.session.gate.prepare.clone();
        let _ = self.session.replace_content(now, prepare);
    }

    /// The store replaced the issued request with the re-simulated one (`ApprovalStore::replace`).
    ///
    /// Documented exception (plan H1, pinned by `s4_flow/flow.txt` `resim_same_after_click`):
    /// `issued` is the replaced request at once, while the session keeps the content it drew
    /// until [`Self::resim_shown`]. After a click whose re-simulation came back `Same`, the
    /// caller consumes `issued` (the replaced digest) without redrawing; the old digest is no
    /// longer usable.
    pub(crate) fn resim_replaced(&mut self, request: ApprovalRequest, prepared: Box<Prepared>) {
        self.issued = Some(request);
        self.prepared = Some(prepared);
        self.resim_click = false;
    }

    /// The re-simulated request is shown (no click, or not `Same`): the status says what changed,
    /// then the content is replaced (a new approval).
    pub(crate) fn resim_shown(&mut self, kind: ResimKind, request: ApprovalRequest, now: u64) {
        self.status = match kind {
            ResimKind::Same => None,
            ResimKind::Changed | ResimKind::Blocked | ResimKind::Failed => Some(format!(
                "{}{}",
                text::SIM_CHANGED.get(self.lang),
                text::SIM_CHANGED_STEP.get(self.lang)
            )),
            ResimKind::NoResult => Some(format!(
                "{}{}",
                text::SIM_RESIM_FAILED.get(self.lang),
                text::SIM_RESIM_FAILED_STEP.get(self.lang)
            )),
        };
        let _ = self.session.replace_content(
            now,
            PrepareState::Ready(ReadyContent::Signing(Box::new(request))),
        );
    }
}

#[cfg(test)]
mod tests {
    //! `ApprovalFlow::on_event` applies the gate's foreground sample before the event (spec/04
    //! §3.4, AGENTS.md §6 arm delay and re-activation; 2026-11-19, S4 B4 review); activation
    //! restarts the delay unconditionally and a connect toggle from an older view is dropped
    //! (2026-11-19, S4 B6). Headless: a
    //! flow without a window, driven at fixed times. The `s4_flow` goldens cannot show the order
    //! because their harness keeps the foreground steady between events.

    use yw_core::evm::address::parse_address;
    use yw_core::evm::chain::SEPOLIA;
    use yw_core::lang::Lang;
    use yw_core::policy::{BrowserOrigin, Family, Method};
    use yw_engine::approval::flow::{ShownId, StatusAction};
    use yw_engine::approval::interaction::{APPROVE_ARM_DELAY_MS, InteractionEvent};
    use yw_engine::approval::view::ApprovalView;
    use yw_engine::browser::envelope::{Correlation, Id16, Id32};
    use yw_engine::browser::{Reply, SiteKind, SiteRequest};

    use super::ApprovalFlow;
    use crate::app_approval::ConnectState;
    use crate::app_chain_sites::ConnectChoice;
    use crate::app_evm::QueuedItem;

    const START: u64 = 1_000_000;

    const ENTER: InteractionEvent = InteractionEvent::ApproveActivated { physical: true };

    /// A Ready EVM connect window with its one account selected (Standard risk, no checkbox),
    /// brought to the front at `START`; returns it after a `Tick` at the first armed instant.
    fn armed() -> (ApprovalFlow, u64) {
        let site = SiteRequest {
            reply: Reply {
                conn: 1,
                correlation: Correlation {
                    session_id: Id32([1; 32]),
                    sequence: 1,
                    activation_nonce: Id32([2; 32]),
                    request_id: Id16([3; 16]),
                },
            },
            origin: BrowserOrigin::parse("https://app.example").unwrap(),
            chain_id: SEPOLIA,
            deadline_ms: u64::MAX,
            method: Method::RequestAccounts,
            kind: SiteKind::RequestAccounts,
            compat_mode: None,
        };
        let account = parse_address("0x9858effd232b4033e47d90003d41ec34ecaeda94").unwrap();
        let connect = ConnectState {
            accounts: vec![(
                ConnectChoice::Evm(account),
                "A".to_owned(),
                "a".to_owned(),
                0,
            )],
            selected: vec![true],
            chain_name: "Sepolia".to_owned(),
            chain_id: SEPOLIA,
            family: Family::Evm,
            groups: 0,
        };
        let mut flow = ApprovalFlow::open(
            ShownId(1),
            Lang::En,
            QueuedItem::Site(Box::new(site)),
            Some(connect),
            None,
            START,
        )
        .unwrap();
        let deadline = flow.gate().deadline_ms;
        flow.connect_ready(deadline, START);
        flow.activated(START);
        let armed_at = START + APPROVE_ARM_DELAY_MS;
        assert_eq!(
            flow.on_event(armed_at, true, InteractionEvent::Tick),
            StatusAction::Repaint
        );
        (flow, armed_at)
    }

    /// The control: armed, foreground and spaced, a physical Enter approves.
    #[test]
    fn an_armed_foreground_enter_approves() {
        let (mut flow, armed_at) = armed();
        assert_eq!(
            flow.on_event(armed_at + 1, true, ENTER),
            StatusAction::Approve
        );
    }

    /// A press handled with a `false` sample (the window lost the foreground in the same
    /// message) is judged against that sample: it never approves, and it restarts the arm delay.
    /// Were the sample applied after the event, the press would see the previous `true` and
    /// approve.
    #[test]
    fn the_foreground_sample_comes_before_the_event() {
        let (mut flow, armed_at) = armed();
        let now = armed_at + 1;
        assert_eq!(flow.on_event(now, false, ENTER), StatusAction::Repaint);
        assert!(!flow.gate().is_foreground);
        assert_eq!(flow.gate().ready_at_ms, now);
    }

    /// After a `false` sample, the next press with a `true` sample is a re-activation first: the
    /// arm delay restarts at that press and it does not approve; a press a full delay later does.
    #[test]
    fn a_press_after_a_lost_foreground_restarts_the_delay() {
        let (mut flow, armed_at) = armed();
        assert_eq!(
            flow.on_event(armed_at + 1, false, InteractionEvent::Tick),
            StatusAction::Repaint
        );
        let back = armed_at + 2;
        assert_eq!(flow.on_event(back, true, ENTER), StatusAction::Repaint);
        assert!(flow.gate().is_foreground);
        assert_eq!(flow.gate().ready_at_ms, back);
        assert_eq!(
            flow.on_event(back + APPROVE_ARM_DELAY_MS - 1, true, ENTER),
            StatusAction::Repaint
        );
        let again = back + APPROVE_ARM_DELAY_MS - 1;
        assert_eq!(
            flow.on_event(again + APPROVE_ARM_DELAY_MS, true, ENTER),
            StatusAction::Approve
        );
    }

    /// `ApprovalSignal::Activated` (2026-11-19, S4 B6, plan D-10): the arm delay restarts even
    /// when the gate is already foreground and armed (unconditional), then the gate is
    /// foreground; an Enter before a full delay does not approve, one after it does.
    #[test]
    fn activation_restarts_the_delay_unconditionally() {
        let (mut flow, armed_at) = armed();
        assert!(flow.gate().is_foreground);
        let at = armed_at + 500;
        flow.activated(at);
        assert!(flow.gate().is_foreground);
        assert_eq!(flow.gate().ready_at_ms, at);
        assert_eq!(
            flow.on_event(at + APPROVE_ARM_DELAY_MS - 1, true, ENTER),
            StatusAction::Repaint
        );
        let again = at + APPROVE_ARM_DELAY_MS - 1;
        assert_eq!(
            flow.on_event(again + APPROVE_ARM_DELAY_MS, true, ENTER),
            StatusAction::Approve
        );
    }

    /// Critique A-13 (2026-11-19, S4 B6): a connect toggle carries the revision of the view its
    /// layout was drawn from; one drawn from an older view changes nothing (selection, count and
    /// checkbox as they were), one drawn from the shown view toggles.
    #[test]
    fn a_toggle_drawn_from_an_older_view_changes_nothing() {
        let (mut flow, armed_at) = armed();
        let old = flow.view_rev();
        flow.set_view(ApprovalView::default());
        let shown = flow.view_rev();
        assert_ne!(old, shown, "a new view is a new revision");
        assert!(!flow.toggle_account(0, old, armed_at + 1));
        assert_eq!(flow.connect().map(|c| c.selected.clone()), Some(vec![true]));
        assert_eq!(flow.gate().connect_selected, 1);
        assert!(flow.toggle_account(0, shown, armed_at + 2));
        assert_eq!(
            flow.connect().map(|c| c.selected.clone()),
            Some(vec![false])
        );
        assert_eq!(flow.gate().connect_selected, 0);
    }
}
