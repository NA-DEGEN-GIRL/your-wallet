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
pub const PRESETS: &[(u16, yw_core::lang::Text, &str)] = &[
    (
        ids::PRESET_OPENAI,
        text::PRESET_OPENAI,
        "https://api.openai.com/v1/chat/completions",
    ),
    (
        ids::PRESET_CLAUDE,
        text::PRESET_CLAUDE,
        "https://api.anthropic.com/v1/chat/completions",
    ),
    (
        ids::PRESET_OPENROUTER,
        text::PRESET_OPENROUTER,
        "https://openrouter.ai/api/v1/chat/completions",
    ),
    (
        ids::PRESET_OLLAMA,
        text::PRESET_OLLAMA,
        "http://127.0.0.1:11434/v1/chat/completions",
    ),
    (
        ids::PRESET_LM_STUDIO,
        text::PRESET_LM_STUDIO,
        "http://127.0.0.1:1234/v1/chat/completions",
    ),
];

/// The S15 `AI 설명` section texts (spec/04 §2.11, spec/06 §2; English spec/14).
pub mod text {
    yw_core::texts! {
        PRESET_OPENAI = "OpenAI" / "OpenAI";
        PRESET_CLAUDE = "Claude" / "Claude";
        PRESET_OPENROUTER = "OpenRouter" / "OpenRouter";
        PRESET_OLLAMA = "Ollama (로컬)" / "Ollama (local)";
        PRESET_LM_STUDIO = "LM Studio (로컬)" / "LM Studio (local)";
        CARD = "AI 설명 (선택 기능)" / "AI explanation (optional)";
        INTRO = "승인 창에 dApp 요청(거래·서명)을 AI가 한국어로 풀어 쓴 참고 설명을 따로 덧붙입니다. 기본은 꺼짐입니다. AI 설명은 틀릴 수 있고, 승인 버튼·위험 표시·경고에는 전혀 쓰이지 않습니다."
            / "Adds a separate reference explanation of dApp requests (transactions, signatures), written by an AI in English, to the approval window. Off by default. AI explanations can be wrong and are never used for the approve button, the risk display or the warnings.";
        STATUS_ON(1) = "상태: 켜짐 — dApp 요청마다 {0}(으)로 요청 내용을 보냅니다"
            / "Status: on — the request content is sent to {0} for every dApp request";
        STATUS_UNUSABLE = "상태: 켜짐으로 저장됐지만 엔드포인트·모델이 없어 쓰지 않습니다"
            / "Status: saved as on, but not used because the endpoint or the model is missing";
        STATUS_OFF = "상태: 꺼짐 — 외부로 아무것도 보내지 않습니다"
            / "Status: off — nothing is sent out";
        ENABLE = "AI 설명 사용" / "Use AI explanations";
        ENABLE_HELP = "켤 때 어떤 정보가 어디로 전송되는지 먼저 보여주고 동의를 받습니다. 지갑에서 직접 만든 보내기(EVM·Solana·Bitcoin)는 설명하지 않습니다."
            / "Turning it on first shows what is sent where and asks for your consent. Sends made in the wallet itself (EVM, Solana, Bitcoin) are not explained.";
        PROVIDER_CARD = "AI 공급자 (OpenAI 호환)" / "AI provider (OpenAI-compatible)";
        PROVIDER_HELP = "OpenAI 호환 채팅 API의 전체 주소입니다(…/chat/completions). https:// 주소, 또는 이 PC에서 돌리는 로컬 모델(http://127.0.0.1 · localhost · [::1])만 허용합니다. 주소를 바꾸면 AI 설명이 꺼지고 다시 동의해야 합니다."
            / "The full address of an OpenAI-compatible chat API (…/chat/completions). Only https:// addresses or a local model on this PC (http://127.0.0.1 · localhost · [::1]) are allowed. Changing the address turns AI explanations off and needs your consent again.";
        QUICK_FILL = "빠른 입력" / "Quick fill";
        QUICK_HELP = "버튼은 엔드포인트 칸만 채웁니다. '저장'해야 바뀝니다. 모델 이름은 공급자 문서에서 확인하세요(OpenRouter는 openai/gpt-… · anthropic/claude-… 형식). Ollama·LM Studio는 이 PC에서 서버를 켜 두어야 합니다."
            / "The buttons only fill the endpoint field; 'Save' applies it. Look up the model name in the provider's documentation (OpenRouter uses openai/gpt-… · anthropic/claude-…). Ollama and LM Studio need their server running on this PC.";
        ENDPOINT = "엔드포인트" / "Endpoint";
        PATH_HINT = "주소가 /chat/completions로 끝나지 않습니다. OpenAI 호환 채팅 API의 전체 주소를 넣으세요(…/v1/responses 같은 다른 API 주소는 HTTP 404가 납니다)."
            / "The address does not end in /chat/completions. Enter the full address of an OpenAI-compatible chat API (another API address such as …/v1/responses answers HTTP 404).";
        ANTHROPIC_NOTE = "Claude(api.anthropic.com의 OpenAI 호환 층): 응답 형식은 json_schema만 받습니다(json_object는 HTTP 400). 추론 강도(reasoning_effort)는 무시합니다. Claude 5 모델은 기본으로 생각(추론)을 하므로 10초 기한에는 빠른 모델(예: claude-haiku-4-5-20251001)이 맞습니다."
            / "Claude (the OpenAI-compatible layer of api.anthropic.com): only the json_schema response format is accepted (json_object answers HTTP 400). The reasoning effort (reasoning_effort) is ignored. Claude 5 models think (reason) by default, so a fast model (e.g. claude-haiku-4-5-20251001) suits the 10-second deadline.";
        MODEL = "모델" / "Model";
        FORMAT = "응답 형식" / "Response format";
        FORMAT_SCHEMA = "json_schema (기본)" / "json_schema (default)";
        OPENAI_NOTE = "api.openai.com에는 max_tokens를 보내지 않습니다(최신 추론 모델이 HTTP 400으로 거부합니다). 다른 주소로 바꾸면 이 값을 다시 씁니다."
            / "max_tokens is not sent to api.openai.com (recent reasoning models refuse it with HTTP 400). It is used again with another address.";
        EFFORT = "추론 강도" / "Reasoning effort";
        EFFORT_NONE = "보내지 않음 (기본)" / "Not sent (default)";
        OPTIONS_HELP = "공급자가 json_schema를 거부하면(HTTP 400) json_object로 바꾸세요. max_tokens는 0이면 보내지 않고, 1–4096이면 그 값을 보냅니다. 추론 강도는 추론 모델이 답하기 전에 생각하는 양(reasoning_effort)입니다. 높을수록 느려져 10초 기한을 넘기 쉽고, 추론 모델이 아니면 HTTP 400으로 거부할 수 있습니다 — 그러면 '보내지 않음'으로 두세요."
            / "If the provider refuses json_schema (HTTP 400), switch to json_object. max_tokens 0 is not sent; 1–4096 is sent as is. The reasoning effort is how much a reasoning model thinks before answering (reasoning_effort). Higher is slower and easily misses the 10-second deadline, and a model that does not reason may refuse it with HTTP 400 — then leave it at 'Not sent'.";
        SAVE = "저장" / "Save";
        TEST = "연결 테스트" / "Test connection";
        TEST_HELP = "연결 테스트는 지어낸 표본 요청(주소 0x…dEaD, 0.01 SepoliaETH)으로 저장된 설정을 한 번 호출해 응답 형식만 확인합니다. 내 주소·거래는 보내지 않고, 켜기 전에도 할 수 있습니다."
            / "The connection test calls the saved settings once with a made-up sample request (address 0x…dEaD, 0.01 SepoliaETH) and checks only the answer format. Your addresses and transactions are not sent, and it works before turning the feature on.";
        TESTING = "연결 테스트 중… (최대 10초)" / "Testing the connection… (up to 10 s)";
        KEY_CARD = "AI API 키" / "AI API key";
        KEY_STATE(1) = "저장된 API 키: {0} (저장된 값은 다시 보이지 않습니다)"
            / "Saved API key: {0} (a saved value is never shown again)";
        KEY_NONE = "없음" / "none";
        KEY_WITHHELD = "다른 엔드포인트 주소용이라 보내지 않음 — API 키를 다시 입력하세요"
            / "for another endpoint address, so not sent — enter the API key again";
        KEY_SET = "설정됨" / "set";
        KEY = "API 키" / "API key";
        KEY_SAVE = "키 저장" / "Save key";
        KEY_DELETE = "키 삭제" / "Delete key";
        KEY_DELETED = "API 키를 지웠습니다." / "API key deleted.";
        KEY_HELP = "로컬 모델처럼 키가 필요 없으면 비워 두세요. 키는 Windows가 이 사용자 계정에서만 풀 수 있게 암호화해 저장하고, 로그에 남기지 않습니다."
            / "Leave it empty when no key is needed, as with a local model. The key is stored encrypted so that only this Windows user account can decrypt it, and it is never logged.";
    }
}

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
        let lang = self.settings.language;
        let t = |text: yw_core::lang::Text| text.get(lang).to_owned();
        let settings = &self.settings.llm_explain;
        let form = &self.llm_ui;
        let saved_endpoint = parse_endpoint(&settings.endpoint);
        items.push(Item::CardStart(Some(t(text::CARD))));
        items.push(Item::Help(t(text::INTRO)));
        let status = if effectively_enabled(settings) {
            text::STATUS_ON.fill(
                lang,
                [&saved_endpoint
                    .as_ref()
                    .map_or_else(String::new, |endpoint| host_phrase(lang, endpoint))],
            )
        } else if settings.enabled {
            t(text::STATUS_UNUSABLE)
        } else {
            t(text::STATUS_OFF)
        };
        items.push(Item::Text(status));
        items.push(Item::Row(vec![Ctl::check(
            ids::ENABLE,
            text::ENABLE.get(lang),
            settings.enabled,
        )]));
        items.push(Item::Help(t(text::ENABLE_HELP)));
        if let Some((message, ok)) = &form.message {
            items.push(Item::Banner(
                message.clone(),
                if *ok { Tone::Success } else { Tone::Danger },
            ));
        }
        items.push(Item::CardEnd);

        items.push(Item::CardStart(Some(t(text::PROVIDER_CARD))));
        items.push(Item::Help(t(text::PROVIDER_HELP)));
        items.push(Item::LabeledRow(
            t(text::QUICK_FILL),
            PRESETS
                .iter()
                .map(|(id, label, _)| Ctl::button(*id, label.get(lang)))
                .collect(),
        ));
        items.push(Item::Help(t(text::QUICK_HELP)));
        let notes = DraftNotes::of(&form.endpoint_text);
        items.push(Item::LabeledRow(
            t(text::ENDPOINT),
            vec![Ctl::edit(
                ids::ENDPOINT_EDIT,
                &form.endpoint_text,
                460,
                false,
                2_048,
            )],
        ));
        if notes.path_hint {
            items.push(Item::Banner(t(text::PATH_HINT), Tone::Warn));
        }
        if notes.anthropic {
            items.push(Item::Help(t(text::ANTHROPIC_NOTE)));
        }
        items.push(Item::LabeledRow(
            t(text::MODEL),
            vec![Ctl::edit(
                ids::MODEL_EDIT,
                &form.model_text,
                260,
                false,
                128,
            )],
        ));
        items.push(Item::LabeledRow(
            t(text::FORMAT),
            vec![
                Ctl::radio(
                    ids::FORMAT_SCHEMA,
                    text::FORMAT_SCHEMA.get(lang),
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
            items.push(Item::Help(t(text::OPENAI_NOTE)));
        }
        let effort = |id: u16, label: &str, value: Option<ReasoningEffort>| {
            Ctl::radio(id, label, form.effort == value, value.is_none())
        };
        items.push(Item::LabeledRow(
            t(text::EFFORT),
            vec![
                effort(ids::EFFORT_NONE, text::EFFORT_NONE.get(lang), None),
                effort(ids::EFFORT_LOW, "low", Some(ReasoningEffort::Low)),
                effort(ids::EFFORT_MEDIUM, "medium", Some(ReasoningEffort::Medium)),
                effort(ids::EFFORT_HIGH, "high", Some(ReasoningEffort::High)),
            ],
        ));
        items.push(Item::Help(t(text::OPTIONS_HELP)));
        items.push(Item::Row(vec![
            Ctl::primary(ids::SAVE, text::SAVE.get(lang)),
            Ctl::button(ids::TEST, text::TEST.get(lang)).enabled(!form.test_running),
        ]));
        items.push(Item::Help(t(text::TEST_HELP)));
        if form.test_running {
            items.push(Item::Muted(t(text::TESTING)));
        } else if let Some((message, ok)) = &form.test_result {
            items.push(Item::Banner(
                message.clone(),
                if *ok { Tone::Success } else { Tone::Danger },
            ));
        }
        items.push(Item::CardEnd);

        items.push(Item::CardStart(Some(t(text::KEY_CARD))));
        let has_key = self.apikeys.has(KeyName::Llm);
        items.push(Item::Help(
            text::KEY_STATE.fill(
                lang,
                [if !has_key {
                    text::KEY_NONE
                } else if self.llm_key_withheld() {
                    text::KEY_WITHHELD
                } else {
                    text::KEY_SET
                }
                .get(lang)],
            ),
        ));
        items.push(Item::LabeledRow(
            t(text::KEY),
            vec![Ctl::edit(ids::KEY_EDIT, "", 320, true, 512)],
        ));
        items.push(Item::Row(vec![
            Ctl::button(ids::KEY_SAVE, text::KEY_SAVE.get(lang)),
            Ctl::danger(ids::KEY_DELETE, text::KEY_DELETE.get(lang)).enabled(has_key),
        ]));
        if form.key_deleted && !has_key {
            items.push(Item::Banner(t(text::KEY_DELETED), Tone::Success));
        }
        items.push(Item::Help(t(text::KEY_HELP)));
        items.push(Item::CardEnd);
    }

    /// The privacy notice of the enable overlay (`None` without a valid saved endpoint).
    #[must_use]
    pub fn llm_notice_text(&self) -> Option<String> {
        parse_endpoint(&self.settings.llm_explain.endpoint)
            .map(|endpoint| privacy_notice(self.settings.language, &endpoint))
    }
}
