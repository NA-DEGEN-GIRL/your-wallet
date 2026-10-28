//! `llm_explain` settings rules, the request configuration and the privacy notice (spec/06 §2).
//!
//! The settings object itself (`crate::settings::LlmSettings`) is plain data; this module decides
//! whether it is usable. A feature that is switched on but has an invalid endpoint or model, or
//! whose accepted notice is older than [`PRIVACY_NOTICE_VERSION`], counts as off (no request).

use yw_core::secret::Zeroizing;
use yw_win::http::EndpointUrl;

use super::ExplainError;
use crate::settings::LlmSettings;

/// The privacy notice version that enabling stores (§2.2). Bump it when the text changes.
pub const PRIVACY_NOTICE_VERSION: u32 = 1;
/// Longest endpoint URL (bytes).
pub const ENDPOINT_MAX_BYTES: usize = 2_048;
/// Longest model name.
pub const MODEL_MAX_BYTES: usize = 128;
/// Longest API key.
pub const API_KEY_MAX_BYTES: usize = 512;
/// Largest `max_tokens`.
pub const MAX_TOKENS_LIMIT: u16 = 4_096;

/// `response_format` (§4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseFormatMode {
    /// `{"type":"json_schema", …}` with the strict schema (default).
    JsonSchema,
    /// `{"type":"json_object"}`.
    JsonObject,
}

impl ResponseFormatMode {
    /// Settings string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JsonSchema => "json_schema",
            Self::JsonObject => "json_object",
        }
    }

    /// Parses the settings string.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "json_schema" => Some(Self::JsonSchema),
            "json_object" => Some(Self::JsonObject),
            _ => None,
        }
    }
}

/// A validated endpoint: the URL, its display host (`host[:port]`) and whether it is loopback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// URL.
    pub url: EndpointUrl,
    /// `host[:port]`, lowercase (display and log only; the path is never shown or logged).
    pub host: String,
    /// `http://127.0.0.1|localhost|[::1]`.
    pub loopback: bool,
}

/// Validates an endpoint string (§2.1, D21): ASCII 1–2048 bytes, `https://<host>[:port]<path>` or
/// `http://(127.0.0.1|localhost|[::1])[:port]<path>`, the path ending in `/chat/completions`, no
/// userinfo, query or fragment.
#[must_use]
pub fn parse_endpoint(text: &str) -> Option<Endpoint> {
    if text.is_empty()
        || text.len() > ENDPOINT_MAX_BYTES
        || !text.is_ascii()
        || text.contains(['@', '?', '#'])
    {
        return None;
    }
    let (rest, loopback) = if let Some(rest) = text.strip_prefix("https://") {
        (rest, false)
    } else if let Some(rest) = text.strip_prefix("http://") {
        (rest, true)
    } else {
        return None;
    };
    let slash = rest.find('/')?;
    let (authority, path) = rest.split_at(slash);
    if authority.is_empty() || !path.ends_with("/chat/completions") {
        return None;
    }
    let url = EndpointUrl::parse(text).ok()?;
    let matches_kind = matches!(
        (&url, loopback),
        (EndpointUrl::Https(_), false) | (EndpointUrl::Loopback(_), true)
    );
    matches_kind.then(|| Endpoint {
        url,
        host: authority.to_ascii_lowercase(),
        loopback,
    })
}

/// `^[A-Za-z0-9._:/@+-]{1,128}$` (§2.1).
#[must_use]
pub fn valid_model(text: &str) -> bool {
    (1..=MODEL_MAX_BYTES).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/@+-".contains(&byte))
}

/// API key: 0x21–0x7E, 1–512 bytes (§2.1).
#[must_use]
pub fn valid_api_key(text: &str) -> bool {
    (1..=API_KEY_MAX_BYTES).contains(&text.len())
        && text.bytes().all(|byte| (0x21..=0x7E).contains(&byte))
}

/// Whether the settings ask for explanations and can make them (§2.1 first bullet).
#[must_use]
pub fn effectively_enabled(settings: &LlmSettings) -> bool {
    settings.enabled
        && parse_endpoint(&settings.endpoint).is_some()
        && valid_model(&settings.model)
        && settings.privacy_notice_version >= u64::from(PRIVACY_NOTICE_VERSION)
}

/// The `{host}` phrase of the notice and the panel footer: loopback endpoints read
/// "이 PC의 로컬 서버(host)".
#[must_use]
pub fn host_phrase(endpoint: &Endpoint) -> String {
    if endpoint.loopback {
        format!("이 PC의 로컬 서버({})", endpoint.host)
    } else {
        endpoint.host.clone()
    }
}

/// The privacy notice of §2.2 for `endpoint` (version [`PRIVACY_NOTICE_VERSION`]).
#[must_use]
pub fn privacy_notice(endpoint: &Endpoint) -> String {
    let host = host_phrase(endpoint);
    [
        format!("AI 설명을 켜면 dApp 요청마다 다음 정보가 {host}(으)로 전송됩니다."),
        "- 내 계정 주소와 체인, 요청한 사이트 주소(origin)".to_owned(),
        "- 받는 주소·컨트랙트 주소·금액·토큰 이름과 심볼".to_owned(),
        "- 시뮬레이션 상태와, 성공했을 때 그 결과(자산 변화, 권한 변경)".to_owned(),
        "- 서명 요청 내용(personal_sign 텍스트, 로그인(SIWE) 문구, 타입 데이터 필드)".to_owned(),
        "공급자는 이 정보와 IP 주소를 기록·보관할 수 있고, 내 주소와 거래 활동을 연결할 수 있습니다."
            .to_owned(),
        "니모닉·개인키·비밀번호·RPC 접속 주소(토큰)는 보내지 않습니다.".to_owned(),
        "AI 설명은 틀릴 수 있으며 승인 판단과 위험 표시에 쓰이지 않습니다.".to_owned(),
    ]
    .join("\n")
}

/// A validated model name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelName(String);

impl ModelName {
    /// Validates.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        valid_model(text).then(|| Self(text.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The LLM API key (`apikeys.dpapi` entry `llm`). Not a wallet secret (D10), but never shown,
/// logged or formatted: `Debug` prints `ApiKey([REDACTED])`.
pub struct ApiKey(Zeroizing<String>);

impl ApiKey {
    /// Validates and copies.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        if !valid_api_key(text) {
            return None;
        }
        let mut owned = Zeroizing::new(String::with_capacity(text.len()));
        owned.push_str(text);
        Some(Self(owned))
    }

    /// The `Authorization` header value `Bearer <key>` in a wiping string.
    #[must_use]
    pub fn bearer(&self) -> Zeroizing<String> {
        let mut value = Zeroizing::new(String::with_capacity(self.0.len().saturating_add(7)));
        value.push_str("Bearer ");
        value.push_str(&self.0);
        value
    }
}

impl core::fmt::Debug for ApiKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ApiKey([REDACTED])")
    }
}

/// Everything one request needs (§9 `LlmConfig`).
#[derive(Debug)]
pub struct LlmConfig {
    endpoint: Endpoint,
    model: ModelName,
    api_key: Option<ApiKey>,
    response_format: ResponseFormatMode,
    max_tokens: u16,
}

impl LlmConfig {
    /// Builds the configuration from parts.
    #[must_use]
    pub const fn new(
        endpoint: Endpoint,
        model: ModelName,
        api_key: Option<ApiKey>,
        response_format: ResponseFormatMode,
        max_tokens: u16,
    ) -> Self {
        Self {
            endpoint,
            model,
            api_key,
            response_format,
            max_tokens,
        }
    }

    /// From the settings (the `enabled` flag and the notice are not checked here: the
    /// connection test runs before consent, §2.2).
    ///
    /// # Errors
    ///
    /// [`ExplainError::NotConfigured`] when the endpoint, model or stored key is invalid.
    pub fn from_settings(settings: &LlmSettings, key: Option<&str>) -> Result<Self, ExplainError> {
        let endpoint = parse_endpoint(&settings.endpoint).ok_or(ExplainError::NotConfigured)?;
        let model = ModelName::parse(&settings.model).ok_or(ExplainError::NotConfigured)?;
        let api_key = match key {
            Some(key) => Some(ApiKey::parse(key).ok_or(ExplainError::NotConfigured)?),
            None => None,
        };
        let response_format = ResponseFormatMode::parse(&settings.response_format)
            .unwrap_or(ResponseFormatMode::JsonSchema);
        let max_tokens = u16::try_from(settings.max_tokens)
            .ok()
            .filter(|tokens| *tokens <= MAX_TOKENS_LIMIT)
            .unwrap_or(0);
        Ok(Self::new(
            endpoint,
            model,
            api_key,
            response_format,
            max_tokens,
        ))
    }

    /// The endpoint URL.
    #[must_use]
    pub const fn endpoint(&self) -> &EndpointUrl {
        &self.endpoint.url
    }

    /// The validated endpoint.
    #[must_use]
    pub const fn endpoint_info(&self) -> &Endpoint {
        &self.endpoint
    }

    /// `host[:port]`.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.endpoint.host
    }

    /// Model name.
    #[must_use]
    pub fn model(&self) -> &str {
        self.model.as_str()
    }

    /// The key, if stored.
    #[must_use]
    pub const fn api_key(&self) -> Option<&ApiKey> {
        self.api_key.as_ref()
    }

    /// `response_format`.
    #[must_use]
    pub const fn response_format(&self) -> ResponseFormatMode {
        self.response_format
    }

    /// `max_tokens` (0 = not sent).
    #[must_use]
    pub const fn max_tokens(&self) -> u16 {
        self.max_tokens
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LlmConfig, effectively_enabled, parse_endpoint, privacy_notice, valid_api_key, valid_model,
    };
    use crate::settings::LlmSettings;

    #[test]
    fn e12_endpoint_rules() {
        for bad in [
            "ftp://api.example.org/v1/chat/completions",
            "http://example.com/v1/chat/completions",
            "https://u@api.example.org/v1/chat/completions",
            "https://api.example.org/v1/chat/completions?x=1",
            "https://api.example.org/v1/chat/completions#frag",
            "https://api.example.org/v1/completions",
            "https://api.example.org",
            "http://127.0.0.2:11434/v1/chat/completions",
            "",
        ] {
            assert!(parse_endpoint(bad).is_none(), "{bad}");
        }
        let local = parse_endpoint("http://127.0.0.1:11434/v1/chat/completions").unwrap();
        assert!(local.loopback);
        assert_eq!(local.host, "127.0.0.1:11434");
        let remote = parse_endpoint("https://API.Example.org/v1/chat/completions").unwrap();
        assert!(!remote.loopback);
        assert_eq!(remote.host, "api.example.org");
        assert!(parse_endpoint("http://localhost/v1/chat/completions").is_some());
        assert!(parse_endpoint("http://[::1]:8080/chat/completions").is_some());
    }

    #[test]
    fn model_key_and_effective_state() {
        assert!(valid_model("gpt-4o-mini"));
        assert!(valid_model("qwen2.5:7b-instruct"));
        assert!(!valid_model("a b"));
        assert!(!valid_model(&"a".repeat(129)));
        assert!(valid_api_key("test-key-1"));
        assert!(!valid_api_key("has space"));
        assert!(!valid_api_key(""));
        let mut settings = LlmSettings {
            enabled: true,
            endpoint: "https://api.example.org/v1/chat/completions".to_owned(),
            model: "m".to_owned(),
            privacy_notice_version: 1,
            ..LlmSettings::default()
        };
        assert!(effectively_enabled(&settings));
        settings.privacy_notice_version = 0;
        assert!(!effectively_enabled(&settings));
        settings.privacy_notice_version = 1;
        settings.model.clear();
        assert!(!effectively_enabled(&settings));
        assert!(!effectively_enabled(&LlmSettings::default()));
        assert!(LlmConfig::from_settings(&LlmSettings::default(), None).is_err());
    }

    #[test]
    fn notice_names_the_host() {
        let remote = parse_endpoint("https://api.example.org/v1/chat/completions").unwrap();
        let text = privacy_notice(&remote);
        assert!(text.starts_with("AI 설명을 켜면 dApp 요청마다 다음 정보가 api.example.org(으)로"));
        assert!(text.contains("니모닉·개인키·비밀번호·RPC 접속 주소(토큰)는 보내지 않습니다."));
        let local = parse_endpoint("http://127.0.0.1:11434/v1/chat/completions").unwrap();
        assert!(privacy_notice(&local).contains("이 PC의 로컬 서버(127.0.0.1:11434)(으)로"));
    }
}
