//! Korean native UI for the standalone Sepolia-only development wallet.
//!
//! This module owns no cryptographic or RPC implementation. Potentially slow
//! work is sent to one backend worker so Argon2 and network calls cannot freeze
//! the `egui` event loop.

use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};
use zeroize::{Zeroize, Zeroizing};

const MINIMUM_PASSWORD_BYTES: usize = 12;
const SEND_HOLD_DURATION: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StatusPalette {
    warning: Color32,
    error: Color32,
    success: Color32,
    muted: Color32,
}

impl StatusPalette {
    fn from_visuals(visuals: &egui::Visuals) -> Self {
        if visuals.dark_mode {
            Self {
                warning: Color32::from_rgb(255, 209, 102),
                error: Color32::from_rgb(255, 138, 128),
                success: Color32::from_rgb(126, 231, 135),
                muted: Color32::from_rgb(184, 189, 199),
            }
        } else {
            Self {
                warning: Color32::from_rgb(122, 75, 0),
                error: Color32::from_rgb(180, 35, 24),
                success: Color32::from_rgb(20, 108, 46),
                muted: Color32::from_rgb(85, 91, 102),
            }
        }
    }
}

/// Public values the backend may return after creating, opening, or refreshing.
///
/// Deliberately does not implement `Debug`: full wallet addresses must not
/// accidentally enter logs or crash diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct WalletSnapshot {
    /// Full checksummed or lowercase hexadecimal Sepolia account address.
    pub address: String,
    /// Human-readable Sepolia ETH balance without a ticker suffix.
    pub balance_eth: String,
}

/// Result of one accepted Sepolia broadcast.
///
/// Deliberately does not implement `Debug` because transaction hashes are not
/// needed in diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct SendReceipt {
    /// Transaction hash returned only after the backend verifies it.
    pub transaction_hash: String,
}

/// Exact backend-normalized transfer values shown before any signing occurs.
///
/// This deliberately has no `Debug` implementation because it contains full
/// public transaction metadata that is unnecessary in diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct TransferPreview {
    /// Exact normalized recipient.
    pub recipient: String,
    /// Exact normalized native value in Sepolia ETH.
    pub amount_eth: String,
    /// Exact pending nonce as an unsigned decimal integer.
    pub nonce: String,
    /// Maximum priority fee per gas in gwei.
    pub max_priority_fee_per_gas_gwei: String,
    /// Maximum total fee per gas in gwei.
    pub max_fee_per_gas_gwei: String,
    /// Maximum network fee for the fixed native transfer gas limit, in ETH.
    pub max_network_fee_eth: String,
    /// Maximum value plus network fee, in ETH.
    pub max_total_eth: String,
}

/// Secret/network backend used by the standalone testnet demo.
///
/// Implementations must return only short, category-level Korean errors. They
/// must never place passwords, recovery phrases, keys, addresses, raw
/// transactions, RPC URLs, or raw server responses in an error string.
pub trait WalletBackend: Send + 'static {
    /// Create and persist a new Sepolia-only development vault.
    fn create_wallet(&mut self, password: &str) -> Result<WalletSnapshot, String>;

    /// Open the existing local development vault.
    fn open_wallet(&mut self, password: &str) -> Result<WalletSnapshot, String>;

    /// Refresh the selected public address and Sepolia ETH balance.
    fn refresh(&mut self) -> Result<WalletSnapshot, String>;

    /// Validate inputs and freeze exact Sepolia transfer facts without signing.
    fn prepare_transfer(
        &mut self,
        recipient: &str,
        amount_eth: &str,
    ) -> Result<TransferPreview, String>;

    /// Sign and submit only the currently prepared transfer.
    fn confirm_prepared(&mut self) -> Result<SendReceipt, String>;

    /// Invalidate the currently prepared transfer without signing.
    fn cancel_prepared(&mut self) -> Result<(), String>;

    /// Retry only the exact signed transaction durably retained after an
    /// ambiguous prior broadcast. This must never create a fresh signature.
    fn retry_pending(&mut self) -> Result<SendReceipt, String>;
}

/// Prefer the Windows Korean system font so Hangul does not render as boxes.
///
/// Failure is intentionally silent and path-free; `egui` keeps its bundled
/// fallback fonts if the system font cannot be read.
pub fn install_korean_font(context: &egui::Context) {
    let Some(windows_directory) = std::env::var_os("WINDIR") else {
        return;
    };
    let fonts_directory = std::path::PathBuf::from(windows_directory).join("Fonts");
    let font_bytes = ["malgun.ttf", "malgunsl.ttf"]
        .into_iter()
        .find_map(|name| std::fs::read(fonts_directory.join(name)).ok());
    let Some(font_bytes) = font_bytes else {
        return;
    };

    let mut definitions = egui::FontDefinitions::default();
    definitions.font_data.insert(
        "your-wallet-korean".to_owned(),
        egui::FontData::from_owned(font_bytes).into(),
    );
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        definitions
            .families
            .entry(family)
            .or_default()
            .insert(0, "your-wallet-korean".to_owned());
    }
    context.set_fonts(definitions);
}

enum WorkerCommand {
    Create {
        password: Zeroizing<String>,
    },
    Open {
        password: Zeroizing<String>,
    },
    Refresh,
    PrepareTransfer {
        recipient: String,
        amount_eth: String,
    },
    ConfirmPrepared,
    CancelPrepared,
    RetryPending,
}

enum WorkerEvent {
    Created(Result<WalletSnapshot, String>),
    Opened(Result<WalletSnapshot, String>),
    Refreshed(Result<WalletSnapshot, String>),
    TransferPrepared(Result<TransferPreview, String>),
    PreparedConfirmed(Result<SendReceipt, String>),
    PreparedCancelled(Result<(), String>),
    Retried(Result<SendReceipt, String>),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PendingAction {
    Create,
    Open,
    Refresh,
    PrepareTransfer,
    ConfirmPrepared,
    CancelPrepared,
    RetryPending,
}

impl PendingAction {
    const fn korean(self) -> &'static str {
        match self {
            Self::Create => "새 테스트 지갑을 안전하게 만드는 중...",
            Self::Open => "테스트 지갑을 여는 중...",
            Self::Refresh => "Sepolia 잔액을 확인하는 중...",
            Self::PrepareTransfer => "nonce와 최대 수수료를 확인하는 중...",
            Self::ConfirmPrepared => "확인한 테스트 전송을 서명하고 제출하는 중...",
            Self::CancelPrepared => "준비된 전송을 취소하는 중...",
            Self::RetryPending => "저장된 이전 거래를 그대로 다시 전송하는 중...",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HoldOutcome {
    Idle,
    Holding(Duration),
    Triggered,
}

#[derive(Clone, Copy)]
struct HoldInput {
    enabled: bool,
    primary_pressed_on_button: bool,
    primary_down: bool,
    pointer_inside: bool,
    focused: bool,
    escape_pressed: bool,
}

#[derive(Default)]
struct HoldToSend {
    started_at: Option<Instant>,
    fired: bool,
    release_required: bool,
}

impl HoldToSend {
    fn update(&mut self, now: Instant, input: HoldInput) -> HoldOutcome {
        if !input.primary_down {
            self.reset();
            return HoldOutcome::Idle;
        }

        if self.release_required {
            return HoldOutcome::Idle;
        }

        if !input.enabled || !input.focused || input.escape_pressed {
            self.cancel_current_press();
            return HoldOutcome::Idle;
        }

        if self.started_at.is_some() && !input.pointer_inside {
            self.cancel_current_press();
            return HoldOutcome::Idle;
        }

        let started_at = if let Some(started_at) = self.started_at {
            started_at
        } else if input.primary_pressed_on_button && input.pointer_inside {
            self.started_at = Some(now);
            now
        } else {
            self.cancel_current_press();
            return HoldOutcome::Idle;
        };
        let elapsed = now.saturating_duration_since(started_at);
        if elapsed >= SEND_HOLD_DURATION && !self.fired {
            self.fired = true;
            return HoldOutcome::Triggered;
        }
        HoldOutcome::Holding(elapsed.min(SEND_HOLD_DURATION))
    }

    fn reset(&mut self) {
        self.started_at = None;
        self.fired = false;
        self.release_required = false;
    }

    fn cancel_current_press(&mut self) {
        self.started_at = None;
        self.fired = false;
        self.release_required = true;
    }

    fn fraction(&self, now: Instant) -> f32 {
        self.started_at.map_or(0.0, |started_at| {
            (now.saturating_duration_since(started_at).as_secs_f32()
                / SEND_HOLD_DURATION.as_secs_f32())
            .clamp(0.0, 1.0)
        })
    }
}

/// Standalone Sepolia development-wallet application.
pub struct WalletApp {
    commands: Option<Sender<WorkerCommand>>,
    events: Receiver<WorkerEvent>,
    password: String,
    password_visible: bool,
    snapshot: Option<WalletSnapshot>,
    recipient: String,
    amount_eth: String,
    prepared: Option<TransferPreview>,
    pending: Option<PendingAction>,
    hold: HoldToSend,
    notice: Option<String>,
    error: Option<String>,
    last_transaction_hash: Option<String>,
}

impl WalletApp {
    /// Start the UI and move the backend into its dedicated worker thread.
    #[must_use]
    pub fn new(backend: Box<dyn WalletBackend>) -> Self {
        let (command_sender, command_receiver) = mpsc::channel();
        let (event_sender, event_receiver) = mpsc::channel();
        spawn_worker(backend, command_receiver, event_sender);
        Self {
            commands: Some(command_sender),
            events: event_receiver,
            password: String::new(),
            password_visible: false,
            snapshot: None,
            recipient: String::new(),
            amount_eth: String::new(),
            prepared: None,
            pending: None,
            hold: HoldToSend::default(),
            notice: None,
            error: None,
            last_transaction_hash: None,
        }
    }

    /// Build a visible fail-closed screen when backend initialization failed.
    #[must_use]
    pub fn unavailable(message: impl Into<String>) -> Self {
        let (_sender, receiver) = mpsc::channel();
        Self {
            commands: None,
            events: receiver,
            password: String::new(),
            password_visible: false,
            snapshot: None,
            recipient: String::new(),
            amount_eth: String::new(),
            prepared: None,
            pending: None,
            hold: HoldToSend::default(),
            notice: None,
            error: Some(message.into()),
            last_transaction_hash: None,
        }
    }

    fn send_command(&mut self, command: WorkerCommand, action: PendingAction) {
        self.error = None;
        self.notice = None;
        let accepted = self
            .commands
            .as_ref()
            .is_some_and(|sender| sender.send(command).is_ok());
        if accepted {
            self.pending = Some(action);
        } else {
            self.pending = None;
            self.error =
                Some("지갑 백엔드를 사용할 수 없습니다. 앱을 다시 실행해 주세요.".to_owned());
        }
    }

    fn create_wallet(&mut self) {
        if !valid_password(&self.password) {
            self.error = Some("비밀번호는 UTF-8 기준 12바이트 이상 입력해 주세요.".to_owned());
            return;
        }
        let password = Zeroizing::new(std::mem::take(&mut self.password));
        self.send_command(WorkerCommand::Create { password }, PendingAction::Create);
    }

    fn open_wallet(&mut self) {
        if !valid_password(&self.password) {
            self.error = Some("비밀번호는 UTF-8 기준 12바이트 이상 입력해 주세요.".to_owned());
            return;
        }
        let password = Zeroizing::new(std::mem::take(&mut self.password));
        self.send_command(WorkerCommand::Open { password }, PendingAction::Open);
    }

    fn refresh(&mut self) {
        self.send_command(WorkerCommand::Refresh, PendingAction::Refresh);
    }

    fn prepare_transfer(&mut self) {
        let recipient = self.recipient.trim().to_owned();
        let amount_eth = self.amount_eth.trim().to_owned();
        self.hold.reset();
        self.send_command(
            WorkerCommand::PrepareTransfer {
                recipient,
                amount_eth,
            },
            PendingAction::PrepareTransfer,
        );
    }

    fn confirm_prepared(&mut self) {
        if self.prepared.is_none() {
            self.error = Some("먼저 전송 내용을 준비해 주세요.".to_owned());
            self.hold.reset();
            return;
        }
        self.hold.reset();
        self.send_command(
            WorkerCommand::ConfirmPrepared,
            PendingAction::ConfirmPrepared,
        );
    }

    fn cancel_prepared(&mut self) {
        if self.prepared.is_none() {
            return;
        }
        self.hold.reset();
        self.send_command(WorkerCommand::CancelPrepared, PendingAction::CancelPrepared);
    }

    fn retry_pending(&mut self) {
        self.hold.reset();
        self.send_command(WorkerCommand::RetryPending, PendingAction::RetryPending);
    }

    fn process_events(&mut self) {
        loop {
            let event = match self.events.try_recv() {
                Ok(event) => event,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if self.commands.is_some() && self.pending.is_some() {
                        self.pending = None;
                        self.commands = None;
                        self.error = Some(
                            "지갑 백엔드가 중단되었습니다. 앱을 다시 실행해 주세요.".to_owned(),
                        );
                    }
                    break;
                }
            };
            self.apply_worker_event(event);
        }
    }

    fn apply_worker_event(&mut self, event: WorkerEvent) {
        self.pending = None;
        match event {
            WorkerEvent::Created(result) => match result {
                Ok(snapshot) => {
                    clear_prepared_state(&mut self.prepared, &mut self.hold);
                    self.snapshot = Some(snapshot);
                    self.notice = Some(
                        "새 테스트 지갑을 만들었습니다. 키는 로컬 암호화 파일에만 저장됩니다."
                            .to_owned(),
                    );
                }
                Err(error) => self.error = Some(safe_error(error)),
            },
            WorkerEvent::Opened(result) => match result {
                Ok(snapshot) => {
                    clear_prepared_state(&mut self.prepared, &mut self.hold);
                    self.snapshot = Some(snapshot);
                    self.notice = Some("테스트 지갑을 열었습니다.".to_owned());
                }
                Err(error) => self.error = Some(safe_error(error)),
            },
            WorkerEvent::Refreshed(result) => match result {
                Ok(snapshot) => {
                    self.snapshot = Some(snapshot);
                    self.notice = Some("Sepolia 잔액을 새로 확인했습니다.".to_owned());
                }
                Err(error) => self.error = Some(safe_error(error)),
            },
            WorkerEvent::TransferPrepared(result) => match result {
                Ok(preview) => {
                    self.prepared = Some(preview);
                    self.notice = None;
                    self.error = None;
                    self.hold.reset();
                }
                Err(error) => {
                    self.prepared = None;
                    self.error = Some(safe_error(error));
                }
            },
            WorkerEvent::PreparedConfirmed(result) => match result {
                Ok(receipt) => {
                    self.prepared = None;
                    self.last_transaction_hash = Some(receipt.transaction_hash);
                    self.recipient.clear();
                    self.amount_eth.clear();
                    self.notice = Some(
                        "Sepolia 테스트 전송을 제출했습니다. 반영까지 잠시 걸릴 수 있습니다."
                            .to_owned(),
                    );
                }
                Err(error) => {
                    self.prepared = None;
                    self.error = Some(safe_error(error));
                }
            },
            WorkerEvent::PreparedCancelled(result) => match result {
                Ok(()) => {
                    clear_prepared_state(&mut self.prepared, &mut self.hold);
                    self.notice = Some("준비한 전송을 취소했습니다.".to_owned());
                }
                Err(error) => self.error = Some(safe_error(error)),
            },
            WorkerEvent::Retried(result) => match result {
                Ok(receipt) => {
                    self.last_transaction_hash = Some(receipt.transaction_hash);
                    self.notice =
                        Some("저장된 이전 Sepolia 거래를 그대로 다시 제출했습니다.".to_owned());
                }
                Err(error) => self.error = Some(safe_error(error)),
            },
        }
    }

    fn wallet_setup(&mut self, ui: &mut egui::Ui) {
        let setup_enabled = self.pending.is_none() && self.prepared.is_none();
        let palette = StatusPalette::from_visuals(ui.visuals());
        ui.heading("1. 테스트 지갑 준비");
        ui.label("처음이면 새 지갑을 만들고, 이미 만들었다면 같은 비밀번호로 열어 주세요.");
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let mut edit = egui::TextEdit::singleline(&mut self.password)
                .hint_text("비밀번호 (12바이트 이상)")
                .desired_width(320.0);
            if !self.password_visible {
                edit = edit.password(true);
            }
            let _ = ui.add_enabled(setup_enabled, edit);
            let label = if self.password_visible {
                "숨기기"
            } else {
                "보기"
            };
            if ui.button(label).clicked() {
                self.password_visible = !self.password_visible;
            }
        });
        ui.label(
            RichText::new("지갑 파일 또는 비밀번호를 잃으면 복구할 수 없습니다.")
                .small()
                .color(palette.muted),
        );
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(setup_enabled, egui::Button::new("새 테스트 지갑 만들기"))
                .clicked()
            {
                self.create_wallet();
            }
            if ui
                .add_enabled(setup_enabled, egui::Button::new("기존 테스트 지갑 열기"))
                .clicked()
            {
                self.open_wallet();
            }
        });
    }

    fn account_panel(&mut self, ui: &mut egui::Ui) {
        let Some(snapshot) = self.snapshot.clone() else {
            return;
        };
        ui.separator();
        ui.heading("2. 내 Sepolia 계정");
        ui.label("주소");
        ui.horizontal_wrapped(|ui| {
            ui.monospace(&snapshot.address);
            if ui.button("주소 복사").clicked() {
                ui.ctx().copy_text(snapshot.address.clone());
                self.notice = Some("주소를 복사했습니다.".to_owned());
            }
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("잔액:");
            ui.strong(format!("{} Sepolia ETH", snapshot.balance_eth));
            if ui
                .add_enabled(
                    self.pending.is_none() && self.prepared.is_none(),
                    egui::Button::new("새로고침"),
                )
                .clicked()
            {
                self.refresh();
            }
        });
    }

    fn send_panel(&mut self, context: &egui::Context, ui: &mut egui::Ui) {
        if self.snapshot.is_none() {
            return;
        }
        let palette = StatusPalette::from_visuals(ui.visuals());
        ui.separator();
        ui.heading("3. 테스트 ETH 보내기");
        let preparing_allowed = self.prepared.is_none() && self.pending.is_none();
        if self.prepared.is_none() {
            ui.label("먼저 받는 주소와 금액을 입력해 전송 내용을 준비하세요.");
            ui.add_space(6.0);
            ui.label("받는 주소");
            let _ = ui.add_enabled(
                preparing_allowed,
                egui::TextEdit::singleline(&mut self.recipient)
                    .hint_text("0x로 시작하는 주소")
                    .desired_width(f32::INFINITY),
            );
            if !self.recipient.trim().is_empty() && !valid_recipient_shape(self.recipient.trim()) {
                ui.colored_label(palette.error, "받는 주소 형식을 확인해 주세요.");
            }
            ui.label("보낼 금액");
            ui.horizontal(|ui| {
                let _ = ui.add_enabled(
                    preparing_allowed,
                    egui::TextEdit::singleline(&mut self.amount_eth)
                        .hint_text("예: 0.001")
                        .desired_width(180.0),
                );
                ui.label("Sepolia ETH");
            });
            if !self.amount_eth.trim().is_empty() && !valid_amount_shape(self.amount_eth.trim()) {
                ui.colored_label(
                    palette.error,
                    "0보다 큰 금액을 소수점 아래 최대 18자리로 입력해 주세요.",
                );
            }
            ui.add_space(8.0);
            let valid_input = valid_recipient_shape(self.recipient.trim())
                && valid_amount_shape(self.amount_eth.trim());
            if ui
                .add_enabled(
                    preparing_allowed && valid_input,
                    egui::Button::new("전송 내용 준비").min_size(egui::vec2(180.0, 38.0)),
                )
                .clicked()
            {
                self.prepare_transfer();
            }
            self.hold.reset();
        } else {
            let Some(preview) = self.prepared.clone() else {
                self.hold.reset();
                return;
            };
            ui.colored_label(
                palette.warning,
                RichText::new("아래 내용 그대로 서명·전송됩니다. 전부 확인하세요.").strong(),
            );
            ui.add_space(8.0);
            ui.group(|ui| render_transfer_preview(ui, &preview));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(self.pending.is_none(), egui::Button::new("취소하고 수정"))
                    .clicked()
                {
                    self.cancel_prepared();
                }

                let confirm_enabled = confirmation_enabled(self.prepared.as_ref(), self.pending);
                let response = ui.add_enabled(confirm_enabled, hold_to_send_button());
                let now = Instant::now();
                let outcome = self
                    .hold
                    .update(now, hold_to_send_input(context, &response, confirm_enabled));
                if matches!(outcome, HoldOutcome::Triggered) {
                    self.confirm_prepared();
                } else if matches!(outcome, HoldOutcome::Holding(_)) {
                    context.request_repaint_after(Duration::from_millis(16));
                }
            });
            let now = Instant::now();
            let progress = self.hold.fraction(now);
            let _ = ui.add(
                egui::ProgressBar::new(progress)
                    .desired_width(300.0)
                    .text(format!("{:.1} / 2.0초", progress * 2.0)),
            );
        }

        if let Some(hash) = &self.last_transaction_hash {
            ui.add_space(8.0);
            ui.label("최근 제출한 트랜잭션");
            ui.horizontal_wrapped(|ui| {
                ui.monospace(hash);
                if ui.button("해시 복사").clicked() {
                    ui.ctx().copy_text(hash.clone());
                }
            });
        }

        ui.add_space(12.0);
        ui.collapsing("전송 중 네트워크가 끊겼나요?", |ui| {
            ui.label(
                "새 거래를 만들지 않고, 디스크에 보관된 이전 거래가 있을 때만 같은 바이트를 다시 전송합니다.",
            );
            if ui
                .add_enabled(
                    self.pending.is_none() && self.prepared.is_none(),
                    egui::Button::new("이전 거래 그대로 다시 전송"),
                )
                .clicked()
            {
                self.retry_pending();
            }
        });
    }
}

fn hold_to_send_button() -> egui::Button<'static> {
    egui::Button::new("확인하고 전송 — 2초 동안 누르기")
        .sense(egui::Sense::drag())
        .min_size(egui::vec2(300.0, 48.0))
}

fn hold_to_send_input(
    context: &egui::Context,
    response: &egui::Response,
    enabled: bool,
) -> HoldInput {
    let pointer_inside = response.contains_pointer();
    context.input(|input| HoldInput {
        enabled,
        primary_pressed_on_button: input.pointer.primary_pressed() && pointer_inside,
        primary_down: input.pointer.primary_down(),
        pointer_inside,
        focused: input.focused,
        escape_pressed: input.key_pressed(egui::Key::Escape),
    })
}

fn confirmation_enabled(
    prepared: Option<&TransferPreview>,
    pending: Option<PendingAction>,
) -> bool {
    prepared.is_some() && pending.is_none()
}

fn clear_prepared_state(prepared: &mut Option<TransferPreview>, hold: &mut HoldToSend) {
    *prepared = None;
    hold.reset();
}

fn preview_fields(preview: &TransferPreview) -> [(&'static str, &str); 7] {
    [
        ("받는 주소", preview.recipient.as_str()),
        ("보낼 금액 (Sepolia ETH)", preview.amount_eth.as_str()),
        ("nonce", preview.nonce.as_str()),
        (
            "최대 우선 수수료 / gas (gwei)",
            preview.max_priority_fee_per_gas_gwei.as_str(),
        ),
        (
            "최대 수수료 / gas (gwei)",
            preview.max_fee_per_gas_gwei.as_str(),
        ),
        (
            "최대 네트워크 수수료 (Sepolia ETH)",
            preview.max_network_fee_eth.as_str(),
        ),
        ("최대 총지출 (Sepolia ETH)", preview.max_total_eth.as_str()),
    ]
}

fn render_transfer_preview(ui: &mut egui::Ui, preview: &TransferPreview) {
    for (label, value) in preview_fields(preview) {
        ui.label(RichText::new(label).strong());
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(value).monospace().size(18.0));
        });
        ui.add_space(7.0);
    }
}

impl Drop for WalletApp {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl eframe::App for WalletApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.process_events();
        egui::TopBottomPanel::top("testnet_warning").show(context, |ui| {
            let palette = StatusPalette::from_visuals(ui.visuals());
            ui.vertical_centered(|ui| {
                ui.heading(RichText::new("SEPOLIA 테스트넷 전용 지갑").color(palette.warning));
                ui.strong("실제 ETH나 실제 가치가 있는 자산을 절대 보내지 마세요.");
                ui.label("고정 네트워크: Ethereum Sepolia · Chain ID 11155111");
            });
        });

        egui::CentralPanel::default().show(context, |ui| {
            let palette = StatusPalette::from_visuals(ui.visuals());
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.set_max_width(820.0);
                ui.add_space(8.0);
                self.wallet_setup(ui);
                self.account_panel(ui);
                self.send_panel(context, ui);

                if let Some(action) = self.pending {
                    ui.add_space(12.0);
                    ui.spinner();
                    ui.label(action.korean());
                    context.request_repaint_after(Duration::from_millis(100));
                }
                if let Some(notice) = &self.notice {
                    ui.add_space(12.0);
                    ui.colored_label(palette.success, notice);
                }
                if let Some(error) = &self.error {
                    ui.add_space(12.0);
                    ui.colored_label(palette.error, error);
                }
                ui.add_space(18.0);
                ui.label(
                    RichText::new(
                        "키는 로컬 암호화 파일에만 저장됩니다. 개발용 단일 PC 테스트판이며 메인넷·토큰·브라우저 연결은 지원하지 않습니다.",
                    )
                    .small()
                    .color(palette.muted),
                );
            });
        });
    }
}

fn spawn_worker(
    mut backend: Box<dyn WalletBackend>,
    commands: Receiver<WorkerCommand>,
    events: Sender<WorkerEvent>,
) {
    std::thread::spawn(move || {
        while let Ok(command) = commands.recv() {
            let event = execute_worker_command(backend.as_mut(), command);
            if events.send(event).is_err() {
                break;
            }
        }
    });
}

fn execute_worker_command(backend: &mut dyn WalletBackend, command: WorkerCommand) -> WorkerEvent {
    match command {
        WorkerCommand::Create { password } => {
            WorkerEvent::Created(backend.create_wallet(password.as_str()))
        }
        WorkerCommand::Open { password } => {
            WorkerEvent::Opened(backend.open_wallet(password.as_str()))
        }
        WorkerCommand::Refresh => WorkerEvent::Refreshed(backend.refresh()),
        WorkerCommand::PrepareTransfer {
            recipient,
            amount_eth,
        } => WorkerEvent::TransferPrepared(backend.prepare_transfer(&recipient, &amount_eth)),
        WorkerCommand::ConfirmPrepared => {
            WorkerEvent::PreparedConfirmed(backend.confirm_prepared())
        }
        WorkerCommand::CancelPrepared => WorkerEvent::PreparedCancelled(backend.cancel_prepared()),
        WorkerCommand::RetryPending => WorkerEvent::Retried(backend.retry_pending()),
    }
}

/// Non-secret evidence produced by the window-free UI smoke harness.
pub(crate) struct HeadlessSmokeEvidence {
    pub(crate) transitions_checked: usize,
    pub(crate) backend_routes_checked: usize,
}

/// Exercise the same transfer button handlers, command router, and UI event
/// reducer as the native application without starting `eframe`.
///
/// The backend is fully in memory and uses only non-address sentinel values.
/// No vault, filesystem, network, mouse, keyboard, or window API is touched.
pub(crate) fn run_headless_smoke() -> Result<HeadlessSmokeEvidence, ()> {
    const RECIPIENT_SENTINEL: &str = "headless-recipient";
    const AMOUNT_SENTINEL: &str = "headless-amount";

    let (command_sender, command_receiver) = mpsc::channel();
    let (_unused_event_sender, event_receiver) = mpsc::channel();
    let mut app = WalletApp {
        commands: Some(command_sender),
        events: event_receiver,
        password: String::new(),
        password_visible: false,
        snapshot: None,
        recipient: RECIPIENT_SENTINEL.to_owned(),
        amount_eth: AMOUNT_SENTINEL.to_owned(),
        prepared: None,
        pending: None,
        hold: HoldToSend::default(),
        notice: None,
        error: None,
        last_transaction_hash: None,
    };
    let mut backend = HeadlessBackend::default();

    app.prepare_transfer();
    if app.pending != Some(PendingAction::PrepareTransfer) {
        return Err(());
    }
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(
            command,
            WorkerCommand::PrepareTransfer {
                recipient,
                amount_eth
            } if recipient == RECIPIENT_SENTINEL && amount_eth == AMOUNT_SENTINEL
        )
    })?;
    if app.pending.is_some() || app.prepared.as_ref() != Some(&headless_preview()) {
        return Err(());
    }

    app.confirm_prepared();
    if app.pending != Some(PendingAction::ConfirmPrepared) {
        return Err(());
    }
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::ConfirmPrepared)
    })?;
    if app.pending.is_some()
        || app.prepared.is_some()
        || !app.recipient.is_empty()
        || !app.amount_eth.is_empty()
        || app.last_transaction_hash.as_deref() != Some("headless-confirmed")
    {
        return Err(());
    }

    app.recipient = RECIPIENT_SENTINEL.to_owned();
    app.amount_eth = AMOUNT_SENTINEL.to_owned();
    app.prepare_transfer();
    if app.pending != Some(PendingAction::PrepareTransfer) {
        return Err(());
    }
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::PrepareTransfer { .. })
    })?;
    if app.pending.is_some() || app.prepared.is_none() {
        return Err(());
    }

    app.cancel_prepared();
    if app.pending != Some(PendingAction::CancelPrepared) {
        return Err(());
    }
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::CancelPrepared)
    })?;
    if app.pending.is_some() || app.prepared.is_some() {
        return Err(());
    }

    app.retry_pending();
    if app.pending != Some(PendingAction::RetryPending) {
        return Err(());
    }
    route_headless_command(&mut app, &command_receiver, &mut backend, |command| {
        matches!(command, WorkerCommand::RetryPending)
    })?;
    if app.pending.is_some()
        || app.last_transaction_hash.as_deref() != Some("headless-retried")
        || backend.calls != ["prepare", "confirm", "prepare", "cancel", "retry"]
        || command_receiver.try_recv().is_ok()
    {
        return Err(());
    }

    Ok(HeadlessSmokeEvidence {
        transitions_checked: 10,
        backend_routes_checked: backend.calls.len(),
    })
}

fn route_headless_command(
    app: &mut WalletApp,
    command_receiver: &Receiver<WorkerCommand>,
    backend: &mut dyn WalletBackend,
    expected: impl FnOnce(&WorkerCommand) -> bool,
) -> Result<(), ()> {
    let command = command_receiver.try_recv().map_err(|_| ())?;
    if !expected(&command) {
        return Err(());
    }
    let event = execute_worker_command(backend, command);
    app.apply_worker_event(event);
    Ok(())
}

fn headless_preview() -> TransferPreview {
    TransferPreview {
        recipient: "headless-recipient".to_owned(),
        amount_eth: "headless-amount".to_owned(),
        nonce: "headless-nonce".to_owned(),
        max_priority_fee_per_gas_gwei: "headless-priority-fee".to_owned(),
        max_fee_per_gas_gwei: "headless-max-fee".to_owned(),
        max_network_fee_eth: "headless-network-fee".to_owned(),
        max_total_eth: "headless-total".to_owned(),
    }
}

#[derive(Default)]
struct HeadlessBackend {
    calls: Vec<&'static str>,
}

impl WalletBackend for HeadlessBackend {
    fn create_wallet(&mut self, _password: &str) -> Result<WalletSnapshot, String> {
        Err("headless operation rejected".to_owned())
    }

    fn open_wallet(&mut self, _password: &str) -> Result<WalletSnapshot, String> {
        Err("headless operation rejected".to_owned())
    }

    fn refresh(&mut self) -> Result<WalletSnapshot, String> {
        Err("headless operation rejected".to_owned())
    }

    fn prepare_transfer(
        &mut self,
        recipient: &str,
        amount_eth: &str,
    ) -> Result<TransferPreview, String> {
        if recipient != "headless-recipient" || amount_eth != "headless-amount" {
            return Err("headless input mismatch".to_owned());
        }
        self.calls.push("prepare");
        Ok(headless_preview())
    }

    fn confirm_prepared(&mut self) -> Result<SendReceipt, String> {
        self.calls.push("confirm");
        Ok(SendReceipt {
            transaction_hash: "headless-confirmed".to_owned(),
        })
    }

    fn cancel_prepared(&mut self) -> Result<(), String> {
        self.calls.push("cancel");
        Ok(())
    }

    fn retry_pending(&mut self) -> Result<SendReceipt, String> {
        self.calls.push("retry");
        Ok(SendReceipt {
            transaction_hash: "headless-retried".to_owned(),
        })
    }
}

fn valid_password(password: &str) -> bool {
    password.len() >= MINIMUM_PASSWORD_BYTES
}

fn valid_recipient_shape(recipient: &str) -> bool {
    recipient.len() == 42
        && recipient.starts_with("0x")
        && recipient.as_bytes()[2..].iter().all(u8::is_ascii_hexdigit)
        && recipient.as_bytes()[2..].iter().any(|byte| *byte != b'0')
}

fn valid_amount_shape(amount: &str) -> bool {
    if amount.is_empty() || !amount.bytes().any(|byte| matches!(byte, b'1'..=b'9')) {
        return false;
    }
    let mut parts = amount.split('.');
    let Some(whole) = parts.next() else {
        return false;
    };
    let fraction = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    fraction.is_none_or(|digits| {
        !digits.is_empty() && digits.len() <= 18 && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn safe_error(error: String) -> String {
    const MAX_SAFE_ERROR_CHARS: usize = 160;
    if error.is_empty()
        || error.chars().count() > MAX_SAFE_ERROR_CHARS
        || error.chars().any(char::is_control)
    {
        "작업을 완료하지 못했습니다. 입력과 네트워크를 확인해 주세요.".to_owned()
    } else {
        error
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HoldInput, HoldOutcome, HoldToSend, SEND_HOLD_DURATION, SendReceipt, StatusPalette,
        TransferPreview, WalletBackend, WalletSnapshot, WorkerCommand, WorkerEvent,
        clear_prepared_state, confirmation_enabled, execute_worker_command, hold_to_send_button,
        hold_to_send_input, preview_fields, run_headless_smoke, safe_error, valid_amount_shape,
        valid_password, valid_recipient_shape,
    };
    use eframe::egui;
    use std::time::{Duration, Instant};

    fn hold_frame_input(time: f64, events: Vec<egui::Event>) -> egui::RawInput {
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::pos2(0.0, 0.0),
                egui::vec2(640.0, 480.0),
            )),
            time: Some(time),
            events,
            ..Default::default()
        }
    }

    fn run_hold_button_frame(
        context: &egui::Context,
        hold: &mut HoldToSend,
        epoch: Instant,
        time: f64,
        events: Vec<egui::Event>,
    ) -> (egui::Rect, HoldOutcome) {
        context.begin_pass(hold_frame_input(time, events));
        let response = egui::CentralPanel::default()
            .show(context, |ui| ui.add_enabled(true, hold_to_send_button()))
            .inner;
        let outcome = hold.update(
            epoch + Duration::from_secs_f64(time),
            hold_to_send_input(context, &response, true),
        );
        let rect = response.rect;
        let _ = context.end_pass();
        (rect, outcome)
    }

    const fn pressed_hold_input(enabled: bool) -> HoldInput {
        HoldInput {
            enabled,
            primary_pressed_on_button: true,
            primary_down: true,
            pointer_inside: true,
            focused: true,
            escape_pressed: false,
        }
    }

    const fn continuing_hold_input(enabled: bool) -> HoldInput {
        HoldInput {
            primary_pressed_on_button: false,
            ..pressed_hold_input(enabled)
        }
    }

    fn linear_srgb_component(component: u8) -> f64 {
        let component = f64::from(component) / 255.0;
        if component <= 0.040_45 {
            component / 12.92
        } else {
            ((component + 0.055) / 1.055).powf(2.4)
        }
    }

    fn relative_luminance(color: egui::Color32) -> f64 {
        0.2126 * linear_srgb_component(color.r())
            + 0.7152 * linear_srgb_component(color.g())
            + 0.0722 * linear_srgb_component(color.b())
    }

    fn contrast_ratio(left: egui::Color32, right: egui::Color32) -> f64 {
        let left = relative_luminance(left);
        let right = relative_luminance(right);
        let lighter = left.max(right);
        let darker = left.min(right);
        (lighter + 0.05) / (darker + 0.05)
    }

    #[test]
    fn password_requires_twelve_utf8_bytes() {
        assert!(!valid_password("12345678901"));
        assert!(valid_password("123456789012"));
        assert!(valid_password("가나다라"));
    }

    #[test]
    fn status_palette_meets_text_contrast_on_light_and_dark_panels() {
        for (theme, visuals) in [
            ("light", egui::Visuals::light()),
            ("dark", egui::Visuals::dark()),
        ] {
            let palette = StatusPalette::from_visuals(&visuals);
            for (role, color) in [
                ("warning", palette.warning),
                ("error", palette.error),
                ("success", palette.success),
                ("muted", palette.muted),
            ] {
                assert_eq!(color.a(), 255, "{theme} {role} must be opaque");
                let ratio = contrast_ratio(color, visuals.panel_fill);
                assert!(
                    ratio >= 4.5,
                    "{theme} {role} contrast {ratio:.3} is below 4.5:1"
                );
            }
        }
    }

    #[test]
    fn production_ui_uses_no_fixed_status_color_aliases() {
        let production = include_str!("ui.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production prefix must exist");
        for fixed_color in [
            "Color32::YELLOW",
            "Color32::LIGHT_RED",
            "Color32::LIGHT_GREEN",
            "Color32::GRAY",
        ] {
            assert!(
                !production.contains(fixed_color),
                "production UI must not use fixed status color {fixed_color}"
            );
        }
    }

    #[test]
    fn hold_must_be_continuous_for_two_seconds() {
        let start = Instant::now();
        let mut hold = HoldToSend::default();
        assert_eq!(
            hold.update(start, pressed_hold_input(true)),
            HoldOutcome::Holding(Duration::ZERO)
        );
        assert!(matches!(
            hold.update(
                start + Duration::from_millis(1_999),
                continuing_hold_input(true)
            ),
            HoldOutcome::Holding(_)
        ));
        assert_eq!(
            hold.update(start + SEND_HOLD_DURATION, continuing_hold_input(true)),
            HoldOutcome::Triggered
        );
        assert!(matches!(
            hold.update(
                start + Duration::from_millis(2_100),
                continuing_hold_input(true)
            ),
            HoldOutcome::Holding(_)
        ));
    }

    #[test]
    fn hold_button_survives_egui_click_timeout_and_resets_on_release() {
        let context = egui::Context::default();
        let epoch = Instant::now();
        let mut hold = HoldToSend::default();

        let (button_rect, outcome) =
            run_hold_button_frame(&context, &mut hold, epoch, 0.0, Vec::new());
        assert_eq!(outcome, HoldOutcome::Idle);
        let pointer = button_rect.center();

        let (_, outcome) = run_hold_button_frame(
            &context,
            &mut hold,
            epoch,
            0.1,
            vec![egui::Event::PointerButton {
                pos: pointer,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::NONE,
            }],
        );
        assert_eq!(outcome, HoldOutcome::Holding(Duration::ZERO));

        let (_, outcome) = run_hold_button_frame(&context, &mut hold, epoch, 1.0, Vec::new());
        assert!(matches!(outcome, HoldOutcome::Holding(_)));

        let (_, outcome) = run_hold_button_frame(&context, &mut hold, epoch, 2.2, Vec::new());
        assert_eq!(outcome, HoldOutcome::Triggered);

        let (_, outcome) = run_hold_button_frame(
            &context,
            &mut hold,
            epoch,
            2.3,
            vec![egui::Event::PointerButton {
                pos: pointer,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }],
        );
        assert_eq!(outcome, HoldOutcome::Idle);
        assert_eq!(hold.fraction(epoch + Duration::from_secs_f64(2.3)), 0.0);
    }

    #[test]
    fn touch_hold_survives_egui_long_touch_timeout() {
        let context = egui::Context::default();
        let epoch = Instant::now();
        let mut hold = HoldToSend::default();

        let (button_rect, outcome) =
            run_hold_button_frame(&context, &mut hold, epoch, 0.0, Vec::new());
        assert_eq!(outcome, HoldOutcome::Idle);
        let pointer = button_rect.center();
        let device_id = egui::TouchDeviceId(1);
        let touch_id = egui::TouchId(1);

        let (_, outcome) = run_hold_button_frame(
            &context,
            &mut hold,
            epoch,
            0.1,
            vec![
                egui::Event::PointerMoved(pointer),
                egui::Event::PointerButton {
                    pos: pointer,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
                egui::Event::Touch {
                    device_id,
                    id: touch_id,
                    phase: egui::TouchPhase::Start,
                    pos: pointer,
                    force: None,
                },
            ],
        );
        assert_eq!(outcome, HoldOutcome::Holding(Duration::ZERO));

        let (_, outcome) = run_hold_button_frame(&context, &mut hold, epoch, 1.0, Vec::new());
        assert!(matches!(outcome, HoldOutcome::Holding(_)));

        let (_, outcome) = run_hold_button_frame(&context, &mut hold, epoch, 2.2, Vec::new());
        assert_eq!(outcome, HoldOutcome::Triggered);

        let (_, outcome) = run_hold_button_frame(
            &context,
            &mut hold,
            epoch,
            2.3,
            vec![
                egui::Event::PointerButton {
                    pos: pointer,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: egui::Modifiers::NONE,
                },
                egui::Event::Touch {
                    device_id,
                    id: touch_id,
                    phase: egui::TouchPhase::End,
                    pos: pointer,
                    force: None,
                },
                egui::Event::PointerGone,
            ],
        );
        assert_eq!(outcome, HoldOutcome::Idle);
    }

    #[test]
    fn releasing_early_resets_hold() {
        let start = Instant::now();
        let mut hold = HoldToSend::default();
        let _ = hold.update(start, pressed_hold_input(true));
        assert_eq!(
            hold.update(
                start + Duration::from_secs(1),
                HoldInput {
                    primary_down: false,
                    ..continuing_hold_input(true)
                }
            ),
            HoldOutcome::Idle
        );
        assert_eq!(
            hold.update(start + Duration::from_secs(3), pressed_hold_input(true)),
            HoldOutcome::Holding(Duration::ZERO)
        );
    }

    #[test]
    fn cancelled_hold_cannot_rearm_until_primary_release() {
        let start = Instant::now();
        let cancellations = [
            HoldInput {
                pointer_inside: false,
                ..continuing_hold_input(true)
            },
            HoldInput {
                focused: false,
                ..continuing_hold_input(true)
            },
            HoldInput {
                escape_pressed: true,
                ..continuing_hold_input(true)
            },
        ];

        for cancellation in cancellations {
            let mut hold = HoldToSend::default();
            assert!(matches!(
                hold.update(start, pressed_hold_input(true)),
                HoldOutcome::Holding(_)
            ));
            assert_eq!(
                hold.update(start + Duration::from_millis(500), cancellation),
                HoldOutcome::Idle
            );
            assert_eq!(
                hold.update(start + Duration::from_secs(1), pressed_hold_input(true)),
                HoldOutcome::Idle
            );
            assert_eq!(
                hold.update(
                    start + Duration::from_millis(1_100),
                    HoldInput {
                        primary_down: false,
                        ..continuing_hold_input(true)
                    }
                ),
                HoldOutcome::Idle
            );
            assert_eq!(
                hold.update(
                    start + Duration::from_millis(1_200),
                    pressed_hold_input(true)
                ),
                HoldOutcome::Holding(Duration::ZERO)
            );
        }
    }

    #[test]
    fn unsafe_backend_error_is_replaced() {
        assert_eq!(safe_error("네트워크 오류".to_owned()), "네트워크 오류");
        assert!(!safe_error("bad\nsecret".to_owned()).contains("secret"));
        assert!(!safe_error("x".repeat(161)).contains(&"x".repeat(161)));
    }

    #[test]
    fn send_input_shape_is_conservative() {
        assert!(valid_recipient_shape(
            "0x1111111111111111111111111111111111111111"
        ));
        assert!(!valid_recipient_shape(
            "0x0000000000000000000000000000000000000000"
        ));
        assert!(!valid_recipient_shape("0x1234"));

        assert!(valid_amount_shape("1"));
        assert!(valid_amount_shape("0.000000000000000001"));
        assert!(!valid_amount_shape("0"));
        assert!(!valid_amount_shape("1e-3"));
        assert!(!valid_amount_shape("0.0000000000000000001"));
    }

    fn exact_preview() -> TransferPreview {
        TransferPreview {
            recipient: "0x1111111111111111111111111111111111111111".to_owned(),
            amount_eth: "0.001".to_owned(),
            nonce: "17".to_owned(),
            max_priority_fee_per_gas_gwei: "1.25".to_owned(),
            max_fee_per_gas_gwei: "3.5".to_owned(),
            max_network_fee_eth: "0.0000735".to_owned(),
            max_total_eth: "0.0010735".to_owned(),
        }
    }

    #[test]
    fn confirmation_hold_is_impossible_without_preview() {
        assert!(!confirmation_enabled(None, None));
        let start = Instant::now();
        let mut hold = HoldToSend::default();
        assert_eq!(
            hold.update(start, pressed_hold_input(confirmation_enabled(None, None))),
            HoldOutcome::Idle
        );
        assert_eq!(
            hold.update(
                start + SEND_HOLD_DURATION,
                continuing_hold_input(confirmation_enabled(None, None))
            ),
            HoldOutcome::Idle
        );
    }

    #[test]
    fn cancel_clears_preview_and_hold() {
        let start = Instant::now();
        let mut hold = HoldToSend::default();
        let _ = hold.update(start, pressed_hold_input(true));
        let mut prepared = Some(exact_preview());
        clear_prepared_state(&mut prepared, &mut hold);
        assert!(prepared.is_none());
        assert_eq!(hold.fraction(start + Duration::from_secs(1)), 0.0);
    }

    #[test]
    fn displayed_preview_fields_are_exact_and_complete() {
        let preview = exact_preview();
        assert_eq!(
            preview_fields(&preview),
            [
                ("받는 주소", preview.recipient.as_str()),
                ("보낼 금액 (Sepolia ETH)", preview.amount_eth.as_str()),
                ("nonce", preview.nonce.as_str()),
                (
                    "최대 우선 수수료 / gas (gwei)",
                    preview.max_priority_fee_per_gas_gwei.as_str()
                ),
                (
                    "최대 수수료 / gas (gwei)",
                    preview.max_fee_per_gas_gwei.as_str()
                ),
                (
                    "최대 네트워크 수수료 (Sepolia ETH)",
                    preview.max_network_fee_eth.as_str()
                ),
                ("최대 총지출 (Sepolia ETH)", preview.max_total_eth.as_str()),
            ]
        );
    }

    #[derive(Default)]
    struct RecordingBackend {
        calls: Vec<&'static str>,
    }

    impl WalletBackend for RecordingBackend {
        fn create_wallet(&mut self, _input: &str) -> Result<WalletSnapshot, String> {
            self.calls.push("create");
            Err("unused".to_owned())
        }

        fn open_wallet(&mut self, _input: &str) -> Result<WalletSnapshot, String> {
            self.calls.push("open");
            Err("unused".to_owned())
        }

        fn refresh(&mut self) -> Result<WalletSnapshot, String> {
            self.calls.push("refresh");
            Err("unused".to_owned())
        }

        fn prepare_transfer(
            &mut self,
            recipient: &str,
            amount_eth: &str,
        ) -> Result<TransferPreview, String> {
            assert_eq!(recipient, "exact recipient");
            assert_eq!(amount_eth, "exact amount");
            self.calls.push("prepare");
            Ok(exact_preview())
        }

        fn confirm_prepared(&mut self) -> Result<SendReceipt, String> {
            self.calls.push("confirm");
            Ok(SendReceipt {
                transaction_hash: "exact hash".to_owned(),
            })
        }

        fn cancel_prepared(&mut self) -> Result<(), String> {
            self.calls.push("cancel");
            Ok(())
        }

        fn retry_pending(&mut self) -> Result<SendReceipt, String> {
            self.calls.push("retry");
            Ok(SendReceipt {
                transaction_hash: "retry hash".to_owned(),
            })
        }
    }

    #[test]
    fn worker_routes_prepare_confirm_cancel_and_retry_exactly() {
        let mut backend = RecordingBackend::default();
        assert!(matches!(
            execute_worker_command(
                &mut backend,
                WorkerCommand::PrepareTransfer {
                    recipient: "exact recipient".to_owned(),
                    amount_eth: "exact amount".to_owned(),
                }
            ),
            WorkerEvent::TransferPrepared(Ok(_))
        ));
        assert!(matches!(
            execute_worker_command(&mut backend, WorkerCommand::ConfirmPrepared),
            WorkerEvent::PreparedConfirmed(Ok(_))
        ));
        assert!(matches!(
            execute_worker_command(&mut backend, WorkerCommand::CancelPrepared),
            WorkerEvent::PreparedCancelled(Ok(()))
        ));
        assert!(matches!(
            execute_worker_command(&mut backend, WorkerCommand::RetryPending),
            WorkerEvent::Retried(Ok(_))
        ));
        assert_eq!(backend.calls, ["prepare", "confirm", "cancel", "retry"]);
    }

    #[test]
    fn headless_smoke_exercises_button_handlers_and_state_reducer() -> Result<(), ()> {
        let evidence = run_headless_smoke()?;
        assert_eq!(evidence.transitions_checked, 10);
        assert_eq!(evidence.backend_routes_checked, 5);
        Ok(())
    }
}
