//! The shown approval's flow state (spec/04 §3, spec/03 §11.5, spec/15 §11.4 S4): the request
//! the window shows, its preparation, the issued approval and the gate with its interaction
//! (`ApprovalSession`). 2026-11-19 (S4 B4a, plan D-7): split out of the yw-app `ApprovalUi` of
//! `app_approval.rs` unchanged; the window, its panel, the AI body and the paint state stay there.
//!
//! Every field is private: the methods below are the only writers of the gate, and each keeps
//! the order of the code it came from (the deadline before `replace_content`, `connect_selected`
//! after it, `submitting` before any dispatch). `issued` is the one handle `consume` and `reject`
//! use. The module names no window type: it moves to yw-engine with the flow at S4d (source check
//! S3 in `app_approval_input_tests.rs`). Not the send flows of `yw_engine::flow`.

use yw_core::approval::{ApprovalRequest, RiskLevel};
use yw_core::evm::eip712::DecodedTypedData;
use yw_core::lang::Lang;
use yw_engine::approval::flow::{StatusAction, session_deadline, status_action};
use yw_engine::approval::interaction::{
    ApprovalGate, ApprovalSession, ConnectView, InteractionError, InteractionEvent,
    InteractionStatus, PrepareStage, PrepareState, ReadyContent,
};
use yw_engine::approval::text;
use yw_engine::approval::view::{ApprovalView, Block};
use yw_engine::errors::ErrorCode;
use yw_engine::flow::evm::prepare::{Prepared, ResimKind};

use crate::app_approval::ConnectState;
use crate::app_evm::QueuedItem;
use crate::ui::approval_input::is_release;

/// The shown approval's flow: today's `ApprovalUi` minus the window, the panel, the AI body and
/// the paint state (spec/15 §11.4 S4, plan §3.1).
pub struct ApprovalFlow {
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
}

/// Names only (D28): never the request, a text or an address.
impl core::fmt::Debug for ApprovalFlow {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ApprovalFlow")
            .field("job", &self.job)
            .field("issued", &self.issued.is_some())
            .finish_non_exhaustive()
    }
}

impl ApprovalFlow {
    /// The flow of a window opening at `now`: the gate starts `Preparing(Building)`, unarmed,
    /// not foreground, with the deadline of `session_deadline` (the site deadline, else `now +
    /// MAX_LIFETIME_MS`; S4 B3).
    ///
    /// # Errors
    ///
    /// [`InteractionError`] for an invalid deadline.
    pub(crate) fn open(
        lang: Lang,
        item: QueuedItem,
        connect: Option<ConnectState>,
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
        })
    }

    // ----- reads ----------------------------------------------------------------------------

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

    /// The gate and its interaction (read-only).
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

    /// The status message.
    pub(crate) fn status(&self) -> Option<&str> {
        self.status.as_deref()
    }

    /// A high-risk hold was let go before 2 s.
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

    /// The view the window draws.
    pub(crate) fn set_view(&mut self, view: ApprovalView) {
        self.view = view;
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
    /// (`status_action`, S4 B3). The order of today's `interaction()` in `app_approval.rs`.
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

    /// Toggles connect entry `index` (when it exists): the gate's selection count follows and
    /// the checkbox is cleared.
    pub(crate) fn toggle_account(&mut self, index: usize, now: u64) {
        if let Some(connect) = self.connect.as_mut()
            && index < connect.selected.len()
        {
            connect.toggle(index);
            self.session.gate.connect_selected = connect.gate_count();
            self.session.set_ack(now, false);
        }
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
