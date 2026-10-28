//! S15 `AI 설명` section (M6, spec/04 §2.11, spec/06 §2): the switch, the OpenAI-compatible
//! endpoint, model, response format and `max_tokens`, the API key (`apikeys.dpapi` entry `llm`,
//! never shown again), the connection test, and the privacy notice overlay shown when enabling.

use crate::apikeys::KeyName;
use crate::app::App;
use crate::explain::ResponseFormatMode;
use crate::explain::config::{effectively_enabled, host_phrase, parse_endpoint, privacy_notice};
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
    ];
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
            "엔드포인트".to_owned(),
            vec![Ctl::edit(
                ids::ENDPOINT_EDIT,
                &form.endpoint_text,
                460,
                false,
                2_048,
            )],
        ));
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
            vec![Ctl::edit(
                ids::MAX_TOKENS_EDIT,
                &form.max_tokens_text,
                100,
                false,
                4,
            )],
        ));
        items.push(Item::Help(
            "공급자가 json_schema를 거부하면(HTTP 400) json_object로 바꾸세요. max_tokens는 0이면 보내지 않고, 1–4096이면 그 값을 보냅니다."
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
            if has_key { "설정됨" } else { "없음" }
        )));
        items.push(Item::LabeledRow(
            "API 키".to_owned(),
            vec![Ctl::edit(ids::KEY_EDIT, "", 320, true, 512)],
        ));
        items.push(Item::Row(vec![
            Ctl::button(ids::KEY_SAVE, "키 저장"),
            Ctl::danger(ids::KEY_DELETE, "키 삭제").enabled(has_key),
        ]));
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
