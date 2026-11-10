//! The app side of the optional AI explanation (M6, spec/06): the `yw-llm` worker's lifecycle,
//! the S15 `AI 설명` commands, the connection test and the per-request log line. The approval
//! window's panel is in `crate::app_approval`.
//!
//! The worker exists only while `llm_explain` is effectively on (spec/06 §9): when it is off,
//! no thread runs, no `WinHTTP` session is opened and the `llm` key is not handed to anyone.
//! "On" also needs the consent recorded in the vault-encrypted settings snapshot for the current
//! endpoint host (review M1): the worker starts only after the check that follows an unlock.

use std::sync::Arc;

use yw_core::approval::ChainFacts;
use yw_core::evm::address::Address;

use crate::apikeys::{ApiKeys, KeyName};
use crate::app::{App, Confirm, Screen, SettingsSection};
use crate::events::UiEvent;
use crate::explain::config::{
    KEY_REENTER_TEXT, StoredKey, effectively_enabled, parse_endpoint, valid_api_key, valid_model,
};
use crate::explain::input::RequestKind;
use crate::explain::panel::Ended;
use crate::explain::{
    ExplainError, ExplainService, ExplainSim, ExplainSource, LlmConfig, LlmDone,
    PRIVACY_NOTICE_VERSION, ReasoningEffort, RequestStats, ResponseFormatMode, build_input,
    explain_once,
};
use crate::logging::{self, Field};
use crate::ui::screens_llm::{DraftNotes, ids, preset_url};

/// How long the UI waits for the old worker when the configuration changes (it is never
/// blocked on `WinHTTP`; a late result is dropped with its channel).
const RECONFIGURE_WAIT_MS: u64 = 50;
/// How long shutdown waits (spec/04 §1.5: at most 2 s for the RPC/read/LLM workers).
pub const SHUTDOWN_WAIT_MS: u64 = 2_000;
/// The connection-test sample account (`0x…dEaD`, spec/06 §2.2): no user data.
pub const SAMPLE_FROM: &str = "0x000000000000000000000000000000000000dEaD";
/// The connection-test sample recipient.
pub const SAMPLE_TO: &str = "0x000000000000000000000000000000000000beef";

/// The S15 `AI 설명` form (drafts until `저장`).
#[derive(Clone, Debug)]
pub struct LlmUi {
    /// Endpoint draft.
    pub endpoint_text: String,
    /// Model draft.
    pub model_text: String,
    /// `max_tokens` draft.
    pub max_tokens_text: String,
    /// Response format draft.
    pub format: ResponseFormatMode,
    /// Reasoning effort draft (`None` = not sent).
    pub effort: Option<ReasoningEffort>,
    /// Result of the last action (text, ok).
    pub message: Option<(String, bool)>,
    /// Connection test result (text, ok).
    pub test_result: Option<(String, bool)>,
    /// A connection test is running.
    pub test_running: bool,
    /// The notice overlay's `이해했습니다`.
    pub notice_checked: bool,
    /// Approval-window serial for LLM results.
    pub next_window: u64,
    /// `키 삭제` was confirmed and done: the key card's completion band.
    pub key_deleted: bool,
}

impl Default for LlmUi {
    fn default() -> Self {
        Self {
            endpoint_text: String::new(),
            model_text: String::new(),
            max_tokens_text: "0".to_owned(),
            format: ResponseFormatMode::JsonSchema,
            effort: None,
            message: None,
            test_result: None,
            test_running: false,
            notice_checked: false,
            next_window: 0,
            key_deleted: false,
        }
    }
}

/// The connection-test sample (spec/06 §2.2 `SAMPLE_INPUT`): 0.01 `SepoliaETH` from `0x…dEaD`
/// to `0x…beef`, simulation `unsupported`, origin `https://example.org`.
///
/// # Errors
///
/// [`ExplainError`] from [`build_input`] (never for this fixed sample).
pub fn sample_input() -> Result<crate::explain::ExplainInput, ExplainError> {
    let parse =
        |text: &str| yw_core::evm::address::parse_address(text).map_err(|_| ExplainError::Schema);
    let from: Address = parse(SAMPLE_FROM)?;
    let to: Address = parse(SAMPLE_TO)?;
    let chain = yw_core::evm::chain::sepolia();
    let tx = yw_core::evm::tx::Eip1559Tx {
        chain_id: chain.chain_id,
        nonce: 0,
        max_priority_fee_per_gas: yw_core::evm::amount::U256::from_u64(1_000_000_000),
        max_fee_per_gas: yw_core::evm::amount::U256::from_u64(30_000_000_000),
        gas_limit: 21_000,
        to,
        value: yw_core::evm::amount::U256::from_u64(10_000_000_000_000_000),
        data: Vec::new(),
        access_list: Vec::new(),
    };
    let decoded = yw_core::evm::decode::DecodedTx {
        call: yw_core::evm::decode::decode_call(&chain, &tx.to, &tx.data),
        tx,
    };
    build_input(
        &ExplainSource::EvmTx(&decoded, ExplainSim::Unsupported),
        "https://example.org",
        &from,
        &chain,
        &ChainFacts::default(),
    )
}

/// The AI input of a prepared dApp transaction (spec/06 §3.1, §4.3): the wallet's own decoding
/// (R4 resolved with the simulation logs when usable) and the simulation status, with the diff
/// only after a successful simulation. `None` for a request blocked before the simulation step
/// (`Skipped`), which is not explained.
#[must_use]
pub fn transaction_input(
    prepared: &crate::flow::evm::prepare::Prepared,
    origin: &str,
    user: &Address,
) -> Option<Result<crate::explain::ExplainInput, ExplainError>> {
    let sim = ExplainSim::of(&prepared.sim)?;
    let tx = &prepared.context.tx;
    let chain = &prepared.context.chain;
    let call = yw_core::evm::decode::decode_call(chain, &tx.to, &tx.data);
    let (call, _) =
        yw_core::evm::decode::resolve_token_standard(&call, &tx.to, prepared.sim.events());
    let decoded = yw_core::evm::decode::DecodedTx {
        tx: tx.clone(),
        call,
    };
    Some(build_input(
        &ExplainSource::EvmTx(&decoded, sim),
        origin,
        user,
        chain,
        &prepared.context.facts,
    ))
}

/// The stored LLM key with the endpoint host it is bound to (spec/06 §2.1).
#[must_use]
pub fn stored_llm_key(keys: &ApiKeys) -> Option<StoredKey<'_>> {
    keys.llm_key().map(|key| StoredKey {
        key,
        host: keys.llm_host(),
    })
}

/// Writes the one log line of a request (spec/06 §8). Never the prompt, input, response, model
/// text, key or endpoint path.
pub fn log_request(host: &str, kind: RequestKind, ended: &Ended, stats: Option<&RequestStats>) {
    let stats = stats.copied().unwrap_or_default();
    let http = stats
        .http
        .map_or(Field::Word("-"), |code| Field::Num(u64::from(code)));
    logging::info(
        "llm",
        "llm_explain",
        &[
            ("gen", Field::Num(ended.generation)),
            ("kind", Field::Word(kind.as_str())),
            ("result", Field::Word(ended.result)),
            ("reason", Field::Word(ended.reason)),
            ("http", http),
            (
                "req_bytes",
                Field::Num(u64::try_from(stats.req_bytes).unwrap_or(u64::MAX)),
            ),
            (
                "resp_bytes",
                Field::Num(u64::try_from(stats.resp_bytes).unwrap_or(u64::MAX)),
            ),
            ("elapsed_ms", Field::Num(ended.elapsed_ms)),
            ("host", Field::LlmHost(host)),
        ],
    );
}

impl App {
    /// (Re)creates or drops the `yw-llm` worker to match the settings and the key (spec/06 §9):
    /// off → `None`; a changed endpoint, model, format, `max_tokens`, reasoning effort or key → a
    /// new worker.
    pub fn llm_reconfigure(&mut self) {
        if let Some(service) = self.llm.take() {
            service.stop(RECONFIGURE_WAIT_MS);
            logging::info("llm", "llm.stopped", &[]);
        }
        let settings = &self.settings.llm_explain;
        if !effectively_enabled(settings) {
            return;
        }
        // Review M1: `settings.json` is plain text. Until the settings were checked against the
        // vault-encrypted snapshot after an unlock (`App::reconcile_settings`), an `enabled`
        // flag in it is not a consent: no worker, nothing sent. Approvals (the only requests)
        // need an unlocked wallet anyway.
        if !self.guard.verified {
            return;
        }
        let Some(events) = self.events.clone() else {
            return;
        };
        let Ok(config) = LlmConfig::from_settings(settings, stored_llm_key(&self.apikeys)) else {
            return;
        };
        if config.key_withheld() {
            // spec/06 §2.1: the key was entered for another endpoint host; it is not sent.
            logging::warn("llm", "llm.key_withheld", &[]);
        }
        let host = config.host().to_owned();
        let sink = Box::new(move |done: LlmDone| {
            if events.push(UiEvent::Llm(Box::new(done))).is_err() {
                logging::warn("llm", "E-APP-005", &[]);
            }
        });
        match ExplainService::start(config, sink) {
            Ok(service) => {
                logging::info("llm", "llm.started", &[("host", Field::LlmHost(&host))]);
                self.llm = Some(service);
            }
            Err(_) => logging::warn("llm", "llm.start_failed", &[]),
        }
    }

    /// Stops the worker at shutdown (spec/04 §1.5).
    pub fn llm_shutdown(&mut self) {
        if let Some(service) = self.llm.take() {
            service.stop(SHUTDOWN_WAIT_MS);
        }
    }

    /// Opens S15 `AI 설명` with the drafts loaded from the settings.
    pub fn open_llm_settings(&mut self) {
        let settings = &self.settings.llm_explain;
        self.llm_ui.endpoint_text.clone_from(&settings.endpoint);
        self.llm_ui.model_text.clone_from(&settings.model);
        self.llm_ui.max_tokens_text = settings.max_tokens.to_string();
        self.llm_ui.format = ResponseFormatMode::parse(&settings.response_format)
            .unwrap_or(ResponseFormatMode::JsonSchema);
        self.llm_ui.effort = settings.reasoning_effort;
        self.llm_ui.message = None;
        self.set_screen(Screen::Settings(SettingsSection::Ai));
    }

    /// `EN_CHANGE` of an AI-section edit; `false` when `id` is not one of them.
    pub fn on_llm_edit_change(&mut self, id: u16) -> bool {
        let read = |app: &Self, max: usize| app.controls.text(id, max).unwrap_or_default();
        match id {
            ids::ENDPOINT_EDIT => {
                let before = DraftNotes::of(&self.llm_ui.endpoint_text);
                self.llm_ui.endpoint_text = read(self, 2_048);
                if DraftNotes::of(&self.llm_ui.endpoint_text) != before {
                    // The path hint and the OpenAI / Claude notes follow the draft.
                    self.refresh();
                }
            }
            ids::MODEL_EDIT => self.llm_ui.model_text = read(self, 128),
            ids::MAX_TOKENS_EDIT => self.llm_ui.max_tokens_text = read(self, 8),
            _ => return false,
        }
        true
    }

    fn llm_message(&mut self, text: &str, ok: bool) {
        self.llm_ui.message = Some((text.to_owned(), ok));
        self.refresh();
    }

    /// `LlmKeyDelete` confirmed: the key goes (E-APP-002 keeps it), with a completion band.
    pub(crate) fn llm_delete_key(&mut self) {
        if self.apikeys.remove(KeyName::Llm) && self.save_apikeys() {
            logging::info("llm", "llm.key_deleted", &[]);
            self.llm_reconfigure();
            self.llm_ui.key_deleted = true;
        }
        self.refresh();
    }

    /// `빠른 입력` (2026-11-11): fills the endpoint draft only — `저장` applies it, with the new
    /// consent a changed endpoint needs (spec/06 §2.1). Claude's layer takes `json_schema` only.
    fn llm_preset(&mut self, url: &str) {
        url.clone_into(&mut self.llm_ui.endpoint_text);
        // The edit keeps its own text; its `EN_CHANGE` arrives while this handler runs and is
        // not seen, so the draft above is set directly.
        self.controls.set_text(ids::ENDPOINT_EDIT, url);
        if DraftNotes::of(url).anthropic {
            self.llm_ui.format = ResponseFormatMode::JsonSchema;
        }
        self.llm_ui.message = None;
        self.refresh();
    }

    fn llm_set_effort(&mut self, effort: Option<ReasoningEffort>) {
        self.llm_ui.effort = effort;
        self.refresh();
    }

    /// AI-section commands; `false` when `id` is not one of them.
    pub fn on_llm_command(&mut self, id: u16) -> bool {
        if let Some(url) = preset_url(id) {
            self.llm_preset(url);
            return true;
        }
        match id {
            ids::SECTION_AI => self.open_llm_settings(),
            ids::ENABLE => self.llm_toggle(),
            ids::FORMAT_SCHEMA => {
                self.llm_ui.format = ResponseFormatMode::JsonSchema;
                self.refresh();
            }
            ids::FORMAT_OBJECT => {
                self.llm_ui.format = ResponseFormatMode::JsonObject;
                self.refresh();
            }
            ids::EFFORT_NONE => self.llm_set_effort(None),
            ids::EFFORT_LOW => self.llm_set_effort(Some(ReasoningEffort::Low)),
            ids::EFFORT_MEDIUM => self.llm_set_effort(Some(ReasoningEffort::Medium)),
            ids::EFFORT_HIGH => self.llm_set_effort(Some(ReasoningEffort::High)),
            ids::SAVE => {
                for edit in [ids::ENDPOINT_EDIT, ids::MODEL_EDIT, ids::MAX_TOKENS_EDIT] {
                    self.on_llm_edit_change(edit);
                }
                self.llm_save();
            }
            ids::TEST => self.llm_test(),
            ids::KEY_SAVE => self.llm_save_key(),
            ids::KEY_DELETE => {
                // The stored key cannot be shown again: asked first (2026-11-10).
                if self.apikeys.has(KeyName::Llm) {
                    self.set_screen(Screen::Confirm(Confirm::LlmKeyDelete));
                }
            }
            ids::NOTICE_CHECK => {
                self.llm_ui.notice_checked =
                    self.controls.checked(ids::NOTICE_CHECK).unwrap_or(false);
                self.refresh();
            }
            _ => return false,
        }
        true
    }

    fn llm_toggle(&mut self) {
        let checked = self.controls.checked(ids::ENABLE).unwrap_or(false);
        let enabled = self.settings.llm_explain.enabled;
        if checked && !enabled {
            let saved = &self.settings.llm_explain;
            if parse_endpoint(&saved.endpoint).is_none() || !valid_model(&saved.model) {
                self.llm_message(
                    "먼저 엔드포인트와 모델을 입력하고 '저장'하세요. 그다음 켤 수 있습니다.",
                    false,
                );
                return;
            }
            if self.llm_key_withheld() {
                self.llm_message(KEY_REENTER_TEXT, false);
                return;
            }
            self.llm_ui.notice_checked = false;
            self.set_screen(Screen::Confirm(Confirm::LlmOn));
        } else if !checked && enabled {
            let mut settings = self.settings.clone();
            settings.llm_explain.enabled = false;
            self.save_settings(settings, "llm_explain");
            self.llm_reconfigure();
            self.llm_message("AI 설명을 껐습니다. 외부로 아무것도 보내지 않습니다.", true);
        } else {
            self.refresh();
        }
    }

    /// Whether a stored LLM key exists but is bound to another endpoint host than the saved one
    /// (or to none), so it is not sent (spec/06 §2.1).
    #[must_use]
    pub fn llm_key_withheld(&self) -> bool {
        LlmConfig::from_settings(&self.settings.llm_explain, stored_llm_key(&self.apikeys))
            .is_ok_and(|config| config.key_withheld())
    }

    /// `켜기` of the notice overlay (spec/06 §2.2): only with `이해했습니다` checked, and not
    /// while the stored key belongs to another endpoint host (spec/06 §2.1).
    pub fn llm_confirm_on(&mut self) {
        if !self.llm_ui.notice_checked {
            self.refresh();
            return;
        }
        if self.llm_key_withheld() {
            self.llm_ui.notice_checked = false;
            self.screen = Screen::Settings(SettingsSection::Ai);
            self.llm_message(KEY_REENTER_TEXT, false);
            return;
        }
        let mut settings = self.settings.clone();
        settings.llm_explain.enabled = true;
        settings.llm_explain.privacy_notice_version = u64::from(PRIVACY_NOTICE_VERSION);
        self.llm_ui.notice_checked = false;
        self.screen = Screen::Settings(SettingsSection::Ai);
        self.save_settings(settings, "llm_explain");
        self.llm_reconfigure();
        let text = if self.settings.llm_explain.enabled {
            "AI 설명을 켰습니다. 다음 dApp 요청부터 승인 창에 참고 설명이 붙습니다."
        } else {
            "설정을 저장하지 못했습니다."
        };
        self.llm_message(text, self.settings.llm_explain.enabled);
    }

    /// `저장` of the S15 form with the current drafts.
    pub(crate) fn llm_save(&mut self) {
        let endpoint = self.llm_ui.endpoint_text.trim().to_owned();
        let model = self.llm_ui.model_text.trim().to_owned();
        if !endpoint.is_empty() && parse_endpoint(&endpoint).is_none() {
            self.llm_message(
                "엔드포인트 형식이 올바르지 않습니다. https://…/chat/completions 또는 http://127.0.0.1(localhost·[::1])…/chat/completions 형식이어야 하고 사용자 이름·?·#를 넣을 수 없습니다.",
                false,
            );
            return;
        }
        if !model.is_empty() && !valid_model(&model) {
            self.llm_message(
                "모델 이름은 영문·숫자와 . _ : / @ + - 만 1–128자로 쓸 수 있습니다.",
                false,
            );
            return;
        }
        let max_tokens = match self.llm_ui.max_tokens_text.trim() {
            "" => Some(0),
            text => text.parse::<u64>().ok().filter(|value| *value <= 4_096),
        };
        let Some(max_tokens) = max_tokens else {
            self.llm_message("max_tokens는 0–4096 사이의 정수여야 합니다.", false);
            return;
        };
        let mut settings = self.settings.clone();
        let had_endpoint = parse_endpoint(&settings.llm_explain.endpoint).is_some();
        let changed_endpoint = settings.llm_explain.endpoint != endpoint;
        settings.llm_explain.endpoint = endpoint;
        settings.llm_explain.model = model;
        settings.llm_explain.max_tokens = max_tokens;
        settings.llm_explain.reasoning_effort = self.llm_ui.effort;
        self.llm_ui
            .format
            .as_str()
            .clone_into(&mut settings.llm_explain.response_format);
        let was_enabled = settings.llm_explain.enabled;
        if changed_endpoint {
            // spec/06 §2.1: a new endpoint needs a new consent.
            settings.llm_explain.enabled = false;
            // The stored key stays bound to the old host: write that binding (an older
            // version's key is bound only in memory at load) before the endpoint changes.
            if self.apikeys.llm_host().is_some() && !self.save_apikeys() {
                self.llm_message("설정을 저장하지 못했습니다.", false);
                return;
            }
        }
        self.save_settings(settings.clone(), "llm_explain");
        if self.settings != settings {
            self.llm_message("설정을 저장하지 못했습니다.", false);
            return;
        }
        // A key entered before any endpoint was saved is bound to the first one saved (a key
        // that is unbound while an endpoint was saved stays unbound: it was never entered for
        // the new host).
        if !had_endpoint
            && let Some(endpoint) = parse_endpoint(&self.settings.llm_explain.endpoint)
            && self.apikeys.bind_llm_host(&endpoint.host)
        {
            logging::info("llm", "llm.key_bound", &[]);
            let _ = self.save_apikeys();
        }
        self.llm_reconfigure();
        let text = if changed_endpoint && was_enabled {
            "저장했습니다. 엔드포인트가 바뀌어 AI 설명을 껐습니다. 다시 켜면 새 주소로 보낸다는 안내를 보여줍니다."
        } else {
            "저장했습니다."
        };
        self.llm_message(text, true);
    }

    fn llm_save_key(&mut self) {
        let units = self.controls.text_wiping(ids::KEY_EDIT, 1_024);
        let key = units
            .map(|units| String::from_utf16_lossy(units.as_slice()))
            .map(yw_core::secret::Zeroizing::new)
            .unwrap_or_default();
        self.controls.clear_text(ids::KEY_EDIT);
        self.llm_store_key(key.trim());
    }

    /// Stores an entered key bound to the saved endpoint's `host[:port]` (spec/06 §2.1;
    /// unbound when no valid endpoint is saved yet: it is bound by the next `저장`).
    pub(crate) fn llm_store_key(&mut self, key: &str) {
        if !valid_api_key(key) {
            self.llm_message(
                "API 키는 공백 없는 영문·숫자·기호(0x21–0x7E) 1–512자여야 합니다.",
                false,
            );
            return;
        }
        let host =
            parse_endpoint(&self.settings.llm_explain.endpoint).map(|endpoint| endpoint.host);
        self.apikeys.set_llm(key, host.as_deref());
        if self.save_apikeys() {
            logging::info("llm", "llm.key_set", &[]);
            self.llm_ui.key_deleted = false;
            self.llm_reconfigure();
            self.llm_message("API 키를 저장했습니다.", true);
        } else {
            self.refresh();
        }
    }

    /// `연결 테스트` (spec/06 §2.2): the fixed sample through §4–§5 once with the saved settings
    /// and key, on a short-lived thread; only the resulting state is shown.
    pub(crate) fn llm_test(&mut self) {
        let config =
            LlmConfig::from_settings(&self.settings.llm_explain, stored_llm_key(&self.apikeys));
        let Ok(config) = config else {
            self.llm_ui.test_result = Some((ExplainError::NotConfigured.panel_text(), false));
            self.refresh();
            return;
        };
        if config.key_withheld() {
            // spec/06 §2.1: nothing is sent; the key must be entered again for this endpoint.
            self.llm_ui.test_result =
                Some((format!("연결 테스트 실패: {KEY_REENTER_TEXT}"), false));
            logging::info(
                "llm",
                "llm.test_done",
                &[("result", Field::Word("KeyWithheld"))],
            );
            self.refresh();
            return;
        }
        let Some(events) = self.events.clone() else {
            return;
        };
        self.llm_ui.test_running = true;
        self.llm_ui.test_result = None;
        let spawned = std::thread::Builder::new()
            .name("yw-llm-test".to_owned())
            .spawn(move || {
                let result = sample_input().and_then(|input| {
                    let transport = crate::explain::WinHttpTransport::new(config.endpoint())
                        .map_err(|_| ExplainError::Network)?;
                    explain_once(&transport, &config, &input).0.map(|_| ())
                });
                let _ = events.push(UiEvent::LlmTest(result));
            });
        if spawned.is_err() {
            self.llm_ui.test_running = false;
        }
        logging::info("llm", "llm.test", &[]);
        self.refresh();
    }

    /// The connection test finished.
    pub fn on_llm_test(&mut self, result: Result<(), ExplainError>) {
        self.llm_ui.test_running = false;
        self.llm_ui.test_result = Some(match result {
            Ok(()) => (
                "연결 테스트 성공: 표본 요청에 대한 AI 설명을 받았고 형식 검사를 통과했습니다."
                    .to_owned(),
                true,
            ),
            Err(error) => (format!("연결 테스트 실패: {}", error.panel_text()), false),
        });
        logging::info(
            "llm",
            "llm.test_done",
            &[(
                "result",
                Field::Word(result.err().map_or("ok", ExplainError::as_str)),
            )],
        );
        self.refresh();
    }

    /// A shared handle to the events queue (tests and the tour attach one).
    #[must_use]
    pub fn events_queue(&self) -> Option<Arc<crate::events::EventQueue>> {
        self.events.clone()
    }

    /// Whether the `yw-llm` worker exists (spec/06 E1: none while the feature is off).
    #[must_use]
    pub const fn llm_running(&self) -> bool {
        self.llm.is_some()
    }
}
