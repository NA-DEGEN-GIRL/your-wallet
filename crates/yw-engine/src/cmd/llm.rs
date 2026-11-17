//! Presses of the S15 `AI 설명` section (`ui::screens_llm` on Windows; spec/06 §2).
//!
//! 2026-11-18 (S3 C3): created.

/// A press of the AI-explanation settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LlmPress {
    /// The settings section `AI 설명`.
    SectionAi,
    /// `AI 설명 사용`: the check box's state when it was pressed (`None`: no such box).
    Enable(Option<bool>),
    /// Response format `json_schema`.
    FormatSchema,
    /// Response format `json_object`.
    FormatObject,
    /// `저장` of the form.
    Save,
    /// `연결 테스트`.
    Test,
    /// `키 저장` (the key comes with the press, `PressInput`).
    KeySave,
    /// `키 삭제` (asks first).
    KeyDelete,
    /// The notice overlay's `이해했습니다`: the box's state when it was pressed.
    NoticeCheck(Option<bool>),
    /// `빠른 입력` `OpenAI`.
    PresetOpenAi,
    /// `빠른 입력` Claude.
    PresetClaude,
    /// `빠른 입력` `OpenRouter`.
    PresetOpenRouter,
    /// `빠른 입력` Ollama (local).
    PresetOllama,
    /// `빠른 입력` LM Studio (local).
    PresetLmStudio,
    /// Reasoning effort: not sent.
    EffortNone,
    /// Reasoning effort `low`.
    EffortLow,
    /// Reasoning effort `medium`.
    EffortMedium,
    /// Reasoning effort `high`.
    EffortHigh,
}
