//! S15 `AI 설명` section (M6, spec/04 §2.11, spec/06 §2): the switch, the OpenAI-compatible
//! endpoint (with the `빠른 입력` presets), model, response format, `max_tokens` and reasoning
//! effort, the API key (`apikeys.dpapi` entry `llm`, never shown again), the connection test,
//! and the privacy notice overlay shown when enabling.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): the builders, their helpers and texts moved to yw-engine
//! `screen::build::llm` (bodies unchanged); this file keeps the control ids of its controls
//! (`ids`), which only the Windows shell has.

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

    /// The press control `id` stands for (2026-11-18, S3 C3: `ui::cmd_table`); the two check
    /// boxes carry their state now. `None` when `id` is not one of this module's presses (the
    /// edits are fields, not presses).
    #[must_use]
    pub fn press_of(
        id: u16,
        controls: &crate::ui::main_window::ControlSet,
    ) -> Option<yw_engine::cmd::LlmPress> {
        use yw_engine::cmd::LlmPress;
        Some(match id {
            SECTION_AI => LlmPress::SectionAi,
            ENABLE => LlmPress::Enable(controls.checked(id)),
            FORMAT_SCHEMA => LlmPress::FormatSchema,
            FORMAT_OBJECT => LlmPress::FormatObject,
            SAVE => LlmPress::Save,
            TEST => LlmPress::Test,
            KEY_SAVE => LlmPress::KeySave,
            KEY_DELETE => LlmPress::KeyDelete,
            NOTICE_CHECK => LlmPress::NoticeCheck(controls.checked(id)),
            PRESET_OPENAI => LlmPress::PresetOpenAi,
            PRESET_CLAUDE => LlmPress::PresetClaude,
            PRESET_OPENROUTER => LlmPress::PresetOpenRouter,
            PRESET_OLLAMA => LlmPress::PresetOllama,
            PRESET_LM_STUDIO => LlmPress::PresetLmStudio,
            EFFORT_NONE => LlmPress::EffortNone,
            EFFORT_LOW => LlmPress::EffortLow,
            EFFORT_MEDIUM => LlmPress::EffortMedium,
            EFFORT_HIGH => LlmPress::EffortHigh,
            _ => return None,
        })
    }

    /// The control id of `press` (the inverse of [`press_of`]).
    #[must_use]
    pub const fn id_of(press: yw_engine::cmd::LlmPress) -> u16 {
        use yw_engine::cmd::LlmPress;
        match press {
            LlmPress::SectionAi => SECTION_AI,
            LlmPress::Enable(_) => ENABLE,
            LlmPress::FormatSchema => FORMAT_SCHEMA,
            LlmPress::FormatObject => FORMAT_OBJECT,
            LlmPress::Save => SAVE,
            LlmPress::Test => TEST,
            LlmPress::KeySave => KEY_SAVE,
            LlmPress::KeyDelete => KEY_DELETE,
            LlmPress::NoticeCheck(_) => NOTICE_CHECK,
            LlmPress::PresetOpenAi => PRESET_OPENAI,
            LlmPress::PresetClaude => PRESET_CLAUDE,
            LlmPress::PresetOpenRouter => PRESET_OPENROUTER,
            LlmPress::PresetOllama => PRESET_OLLAMA,
            LlmPress::PresetLmStudio => PRESET_LM_STUDIO,
            LlmPress::EffortNone => EFFORT_NONE,
            LlmPress::EffortLow => EFFORT_LOW,
            LlmPress::EffortMedium => EFFORT_MEDIUM,
            LlmPress::EffortHigh => EFFORT_HIGH,
        }
    }
}
