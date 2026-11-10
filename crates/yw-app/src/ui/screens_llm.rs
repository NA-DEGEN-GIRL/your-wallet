//! S15 `AI 설명` section (M6, spec/04 §2.11, spec/06 §2): the switch, the OpenAI-compatible
//! endpoint (with the `빠른 입력` presets), model, response format, `max_tokens` and reasoning
//! effort, the API key (`apikeys.dpapi` entry `llm`, never shown again), the connection test,
//! and the privacy notice overlay shown when enabling.

use crate::apikeys::KeyName;
use crate::app::App;
use crate::explain::config::{
    Endpoint, effectively_enabled, endpoint_path_hint, host_phrase, parse_endpoint, privacy_notice,
};
use crate::explain::{ReasoningEffort, ResponseFormatMode};
use crate::ui::main_window::{Ctl, Item, Tone};

/// Command ids of the AI section (10,000–10,099; the whole map is `ui::command_ids`).
pub mod ids {
    /// Settings section `AI 설명`.
    pub const SECTION_AI: u16 = 10_000;
    /// `AI 설명 사용` check.
    pub const ENABLE: u16 = 10_001;
    /// Endpoint edit.
    pub const ENDPOINT_EDIT: u16 = 10_002;
    /// Model edit.
    pub const MODEL_EDIT: u16 = 10_003;
    /// Response format `json_schema`.
    pub const FORMAT_SCHEMA: u16 = 10_004;
    /// Response format `json_object`.
    pub const FORMAT_OBJECT: u16 = 10_005;
    /// `max_tokens` edit.
    pub const MAX_TOKENS_EDIT: u16 = 10_006;
    /// `저장`.
    pub const SAVE: u16 = 10_007;
    /// `연결 테스트`.
    pub const TEST: u16 = 10_008;
    /// API key edit (`ES_PASSWORD`).
    pub const KEY_EDIT: u16 = 10_009;
    /// `키 저장`.
    pub const KEY_SAVE: u16 = 10_010;
    /// `키 삭제`.
    pub const KEY_DELETE: u16 = 10_011;
    /// Notice overlay `이해했습니다`.
    pub const NOTICE_CHECK: u16 = 10_012;
    /// `빠른 입력` `OpenAI`.
    pub const PRESET_OPENAI: u16 = 10_013;
    /// `빠른 입력` `Claude`.
    pub const PRESET_CLAUDE: u16 = 10_014;
    /// `빠른 입력` `OpenRouter`.
    pub const PRESET_OPENROUTER: u16 = 10_015;
    /// `빠른 입력` `Ollama (로컬)`.
    pub const PRESET_OLLAMA: u16 = 10_016;
    /// `빠른 입력` `LM Studio (로컬)`.
    pub const PRESET_LM_STUDIO: u16 = 10_017;
    /// Reasoning effort `보내지 않음`.
    pub const EFFORT_NONE: u16 = 10_018;
    /// Reasoning effort `low`.
    pub const EFFORT_LOW: u16 = 10_019;
    /// Reasoning effort `medium`.
    pub const EFFORT_MEDIUM: u16 = 10_020;
    /// Reasoning effort `high`.
    pub const EFFORT_HIGH: u16 = 10_021;

    /// Every fixed id of this module.
    pub const FIXED: &[u16] = &[
        SECTION_AI,
        ENABLE,
        ENDPOINT_EDIT,
        MODEL_EDIT,
        FORMAT_SCHEMA,
        FORMAT_OBJECT,
        MAX_TOKENS_EDIT,
        SAVE,
        TEST,
        KEY_EDIT,
        KEY_SAVE,
        KEY_DELETE,
        NOTICE_CHECK,
        PRESET_OPENAI,
        PRESET_CLAUDE,
        PRESET_OPENROUTER,
        PRESET_OLLAMA,
        PRESET_LM_STUDIO,
        EFFORT_NONE,
        EFFORT_LOW,
        EFFORT_MEDIUM,
        EFFORT_HIGH,
    ];
}

/// The `빠른 입력` presets (spec/06 §2.1, 2026-11-11): command id, button label, endpoint. A
/// preset only fills the endpoint draft; `저장` (with its consent rule) applies it.
pub const PRESETS: &[(u16, &str, &str)] = &[
    (
        ids::PRESET_OPENAI,
        "OpenAI",
        "https://api.openai.com/v1/chat/completions",
    ),
    (
        ids::PRESET_CLAUDE,
        "Claude",
        "https://api.anthropic.com/v1/chat/completions",
    ),
    (
        ids::PRESET_OPENROUTER,
        "OpenRouter",
        "https://openrouter.ai/api/v1/chat/completions",
    ),
    (
        ids::PRESET_OLLAMA,
        "Ollama (로컬)",
        "http://127.0.0.1:11434/v1/chat/completions",
    ),
    (
        ids::PRESET_LM_STUDIO,
        "LM Studio (로컬)",
        "http://127.0.0.1:1234/v1/chat/completions",
    ),
];

/// The endpoint of preset button `id`.
#[must_use]
pub fn preset_url(id: u16) -> Option<&'static str> {
    PRESETS
        .iter()
        .find(|(preset, ..)| *preset == id)
        .map(|(_, _, url)| *url)
}

/// What the provider card says about the endpoint draft (2026-11-11). The card is drawn again
/// when this changes while typing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DraftNotes {
    /// Looks like a URL but the path does not end in `/chat/completions` (a hint, not a rule).
    pub path_hint: bool,
    /// `api.openai.com`: `max_tokens` is never sent.
    pub openai: bool,
    /// `api.anthropic.com`: `json_schema` only, `reasoning_effort` ignored.
    pub anthropic: bool,
}

impl DraftNotes {
    /// The notes of an endpoint draft.
    #[must_use]
    pub fn of(text: &str) -> Self {
        let endpoint = parse_endpoint(text.trim());
        Self {
            path_hint: endpoint_path_hint(text),
            openai: endpoint.as_ref().is_some_and(Endpoint::is_openai),
            anthropic: endpoint.as_ref().is_some_and(Endpoint::is_anthropic),
        }
    }
}

impl App {
    /// The S15 `AI 설명` section.
    #[expect(
        clippy::too_many_lines,
        reason = "the three cards of the section in order"
    )]
    pub fn llm_settings_section(&self, items: &mut Vec<Item>) {
        let settings = &self.settings.llm_explain;
        let form = &self.llm_ui;
        let saved_endpoint = parse_endpoint(&settings.endpoint);
        items.push(Item::CardStart(Some("AI 설명 (선택 기능)".to_owned())));
        items.push(Item::Help(
            "승인 창에 dApp 요청(거래·서명)을 AI가 한국어로 풀어 쓴 참고 설명을 따로 덧붙입니다. 기본은 꺼짐입니다. AI 설명은 틀릴 수 있고, 승인 버튼·위험 표시·경고에는 전혀 쓰이지 않습니다."
                .to_owned(),
        ));
        let status = if effectively_enabled(settings) {
            format!(
                "상태: 켜짐 — dApp 요청마다 {}(으)로 요청 내용을 보냅니다",
                saved_endpoint
                    .as_ref()
                    .map_or_else(String::new, host_phrase)
            )
        } else if settings.enabled {
            "상태: 켜짐으로 저장됐지만 엔드포인트·모델이 없어 쓰지 않습니다".to_owned()
        } else {
            "상태: 꺼짐 — 외부로 아무것도 보내지 않습니다".to_owned()
        };
        items.push(Item::Text(status));
        items.push(Item::Row(vec![Ctl::check(
            ids::ENABLE,
            "AI 설명 사용",
            settings.enabled,
        )]));
        items.push(Item::Help(
            "켤 때 어떤 정보가 어디로 전송되는지 먼저 보여주고 동의를 받습니다. 지갑에서 직접 만든 보내기(EVM·Solana·Bitcoin)는 설명하지 않습니다."
                .to_owned(),
        ));
        if let Some((message, ok)) = &form.message {
            items.push(Item::Banner(
                message.clone(),
                if *ok { Tone::Success } else { Tone::Danger },
            ));
        }
        items.push(Item::CardEnd);

        items.push(Item::CardStart(Some("AI 공급자 (OpenAI 호환)".to_owned())));
        items.push(Item::Help(
            "OpenAI 호환 채팅 API의 전체 주소입니다(…/chat/completions). https:// 주소, 또는 이 PC에서 돌리는 로컬 모델(http://127.0.0.1 · localhost · [::1])만 허용합니다. 주소를 바꾸면 AI 설명이 꺼지고 다시 동의해야 합니다."
                .to_owned(),
        ));
        items.push(Item::LabeledRow(
            "빠른 입력".to_owned(),
            PRESETS
                .iter()
                .map(|(id, label, _)| Ctl::button(*id, label))
                .collect(),
        ));
        items.push(Item::Help(
            "버튼은 엔드포인트 칸만 채웁니다. '저장'해야 바뀝니다. 모델 이름은 공급자 문서에서 확인하세요(OpenRouter는 openai/gpt-… · anthropic/claude-… 형식). Ollama·LM Studio는 이 PC에서 서버를 켜 두어야 합니다."
                .to_owned(),
        ));
        let notes = DraftNotes::of(&form.endpoint_text);
        items.push(Item::LabeledRow(
            "엔드포인트".to_owned(),
            vec![Ctl::edit(
                ids::ENDPOINT_EDIT,
                &form.endpoint_text,
                460,
                false,
                2_048,
            )],
        ));
        if notes.path_hint {
            items.push(Item::Banner(
                "주소가 /chat/completions로 끝나지 않습니다. OpenAI 호환 채팅 API의 전체 주소를 넣으세요(…/v1/responses 같은 다른 API 주소는 HTTP 404가 납니다)."
                    .to_owned(),
                Tone::Warn,
            ));
        }
        if notes.anthropic {
            items.push(Item::Help(
                "Claude(api.anthropic.com의 OpenAI 호환 층): 응답 형식은 json_schema만 받습니다(json_object는 HTTP 400). 추론 강도(reasoning_effort)는 무시합니다. Claude 5 모델은 기본으로 생각(추론)을 하므로 10초 기한에는 빠른 모델(예: claude-haiku-4-5-20251001)이 맞습니다."
                    .to_owned(),
            ));
        }
        items.push(Item::LabeledRow(
            "모델".to_owned(),
            vec![Ctl::edit(
                ids::MODEL_EDIT,
                &form.model_text,
                260,
                false,
                128,
            )],
        ));
        items.push(Item::LabeledRow(
            "응답 형식".to_owned(),
            vec![
                Ctl::radio(
                    ids::FORMAT_SCHEMA,
                    "json_schema (기본)",
                    form.format == ResponseFormatMode::JsonSchema,
                    true,
                ),
                Ctl::radio(
                    ids::FORMAT_OBJECT,
                    "json_object",
                    form.format == ResponseFormatMode::JsonObject,
                    false,
                ),
            ],
        ));
        items.push(Item::LabeledRow(
            "max_tokens".to_owned(),
            vec![
                Ctl::edit(ids::MAX_TOKENS_EDIT, &form.max_tokens_text, 100, false, 4)
                    .enabled(!notes.openai),
            ],
        ));
        if notes.openai {
            items.push(Item::Help(
                "api.openai.com에는 max_tokens를 보내지 않습니다(최신 추론 모델이 HTTP 400으로 거부합니다). 다른 주소로 바꾸면 이 값을 다시 씁니다."
                    .to_owned(),
            ));
        }
        let effort = |id: u16, label: &str, value: Option<ReasoningEffort>| {
            Ctl::radio(id, label, form.effort == value, value.is_none())
        };
        items.push(Item::LabeledRow(
            "추론 강도".to_owned(),
            vec![
                effort(ids::EFFORT_NONE, "보내지 않음 (기본)", None),
                effort(ids::EFFORT_LOW, "low", Some(ReasoningEffort::Low)),
                effort(ids::EFFORT_MEDIUM, "medium", Some(ReasoningEffort::Medium)),
                effort(ids::EFFORT_HIGH, "high", Some(ReasoningEffort::High)),
            ],
        ));
        items.push(Item::Help(
            "공급자가 json_schema를 거부하면(HTTP 400) json_object로 바꾸세요. max_tokens는 0이면 보내지 않고, 1–4096이면 그 값을 보냅니다. 추론 강도는 추론 모델이 답하기 전에 생각하는 양(reasoning_effort)입니다. 높을수록 느려져 10초 기한을 넘기 쉽고, 추론 모델이 아니면 HTTP 400으로 거부할 수 있습니다 — 그러면 '보내지 않음'으로 두세요."
                .to_owned(),
        ));
        items.push(Item::Row(vec![
            Ctl::primary(ids::SAVE, "저장"),
            Ctl::button(ids::TEST, "연결 테스트").enabled(!form.test_running),
        ]));
        items.push(Item::Help(
            "연결 테스트는 지어낸 표본 요청(주소 0x…dEaD, 0.01 SepoliaETH)으로 저장된 설정을 한 번 호출해 응답 형식만 확인합니다. 내 주소·거래는 보내지 않고, 켜기 전에도 할 수 있습니다."
                .to_owned(),
        ));
        if form.test_running {
            items.push(Item::Muted("연결 테스트 중… (최대 10초)".to_owned()));
        } else if let Some((message, ok)) = &form.test_result {
            items.push(Item::Banner(
                message.clone(),
                if *ok { Tone::Success } else { Tone::Danger },
            ));
        }
        items.push(Item::CardEnd);

        items.push(Item::CardStart(Some("AI API 키".to_owned())));
        let has_key = self.apikeys.has(KeyName::Llm);
        items.push(Item::Help(format!(
            "저장된 API 키: {} (저장된 값은 다시 보이지 않습니다)",
            if !has_key {
                "없음"
            } else if self.llm_key_withheld() {
                "다른 엔드포인트 주소용이라 보내지 않음 — API 키를 다시 입력하세요"
            } else {
                "설정됨"
            }
        )));
        items.push(Item::LabeledRow(
            "API 키".to_owned(),
            vec![Ctl::edit(ids::KEY_EDIT, "", 320, true, 512)],
        ));
        items.push(Item::Row(vec![
            Ctl::button(ids::KEY_SAVE, "키 저장"),
            Ctl::danger(ids::KEY_DELETE, "키 삭제").enabled(has_key),
        ]));
        if form.key_deleted && !has_key {
            items.push(Item::Banner(
                "API 키를 지웠습니다.".to_owned(),
                Tone::Success,
            ));
        }
        items.push(Item::Help(
            "로컬 모델처럼 키가 필요 없으면 비워 두세요. 키는 Windows가 이 사용자 계정에서만 풀 수 있게 암호화해 저장하고, 로그에 남기지 않습니다."
                .to_owned(),
        ));
        items.push(Item::CardEnd);
    }

    /// The privacy notice of the enable overlay (`None` without a valid saved endpoint).
    #[must_use]
    pub fn llm_notice_text(&self) -> Option<String> {
        parse_endpoint(&self.settings.llm_explain.endpoint)
            .map(|endpoint| privacy_notice(&endpoint))
    }
}
