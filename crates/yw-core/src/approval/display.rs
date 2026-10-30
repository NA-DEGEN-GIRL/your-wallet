//! Display model and its canonical bytes/digest (spec/03 §11.2–§11.3).

use core::fmt;

use sha2::{Digest, Sha256};

use super::text::{RiskLevel, Warning, is_valid_display_text};
use crate::codec::transcript::Transcript;
use crate::evm::risk::{request_risk, sort_warnings};

/// Display bytes magic.
pub const DISPLAY_MAGIC: &[u8; 8] = b"YWDSP003";
/// Display digest transcript domain.
pub const DISPLAY_DOMAIN: &str = "your-wallet/v3/display";
/// Maximum bytes of one value.
pub const MAX_DISPLAY_VALUE_BYTES: usize = 270_000;
/// Maximum fields.
pub const MAX_DISPLAY_FIELDS: usize = 1_024;
/// Maximum warnings.
pub const MAX_DISPLAY_WARNINGS: usize = 64;
/// Maximum title bytes (the journal `label`, spec/03 §5.1).
pub const MAX_TITLE_BYTES: usize = 256;
const MAX_SUB_LABEL_BYTES: usize = 1_024;

/// Field key (u16, display order, spec/03 §11.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldKey(pub u16);

impl FieldKey {
    /// 요청 출처.
    pub const ORIGIN: Self = Self(0x0001);
    /// 네트워크.
    pub const NETWORK: Self = Self(0x0002);
    /// 서명 계정.
    pub const ACCOUNT: Self = Self(0x0003);
    /// 받는 주소/컨트랙트.
    pub const TO: Self = Self(0x0101);
    /// 보내는 네이티브 금액.
    pub const VALUE: Self = Self(0x0102);
    /// 호출 내용(제목).
    pub const CALL: Self = Self(0x0103);
    /// 호출 인수.
    pub const CALL_ARG: Self = Self(0x0104);
    /// 보냄.
    pub const SENT: Self = Self(0x0110);
    /// 받음.
    pub const RECEIVED: Self = Self(0x0111);
    /// 승인 변경.
    pub const APPROVAL: Self = Self(0x0112);
    /// 기타 이벤트 N개.
    pub const OTHER_EVENTS: Self = Self(0x0113);
    /// 최대 수수료.
    pub const MAX_FEE: Self = Self(0x0120);
    /// 예상 수수료.
    pub const EXPECTED_FEE: Self = Self(0x0121);
    /// maxFee/tip.
    pub const FEE_PARAMS: Self = Self(0x0122);
    /// 가스 한도.
    pub const GAS_LIMIT: Self = Self(0x0123);
    /// nonce.
    pub const NONCE: Self = Self(0x0124);
    /// 대체 대상 거래.
    pub const REPLACES: Self = Self(0x0125);
    /// 시뮬레이션 기준.
    pub const SIMULATION: Self = Self(0x0130);
    /// 액세스 리스트.
    pub const ACCESS_LIST: Self = Self(0x0140);
    /// calldata.
    pub const CALLDATA: Self = Self(0x0141);
    /// 도메인.
    pub const TD_DOMAIN: Self = Self(0x0301);
    /// 형식.
    pub const TD_SCHEMA: Self = Self(0x0302);
    /// 구조화 필드.
    pub const TD_FIELD: Self = Self(0x0303);
    /// 필드 트리.
    pub const TD_TREE: Self = Self(0x0304);
    /// 메시지 텍스트.
    pub const MESSAGE_TEXT: Self = Self(0x0401);
    /// 메시지 hex.
    pub const MESSAGE_HEX: Self = Self(0x0402);
    /// 바이트 수.
    pub const MESSAGE_BYTES: Self = Self(0x0403);
    /// SIWE 필드.
    pub const SIWE_FIELD: Self = Self(0x0404);
    /// SIWS 필드 (Sign-In-With-Solana).
    pub const SIWS_FIELD: Self = Self(0x0405);
    /// 서명 방식 (Bitcoin BIP137·BIP322, Solana 오프체인 메시지).
    pub const MESSAGE_FORMAT: Self = Self(0x0406);
    /// SOL 받는 주소.
    pub const SOL_TO: Self = Self(0x0501);
    /// SOL 자산·금액.
    pub const SOL_AMOUNT: Self = Self(0x0502);
    /// SOL ATA 생성(SPL, v1.1).
    pub const SOL_ATA: Self = Self(0x0503);
    /// SOL 수수료.
    pub const SOL_FEE: Self = Self(0x0504);
    /// SOL 최대 총 차감.
    pub const SOL_TOTAL: Self = Self(0x0505);
    /// SOL 잔액(RPC 참고).
    pub const SOL_BALANCE: Self = Self(0x0506);
    /// SOL 시뮬레이션(참고).
    pub const SOL_SIMULATION: Self = Self(0x0507);
    /// SOL 유효 시간.
    pub const SOL_VALIDITY: Self = Self(0x0508);
    /// SOL 감사(`intent_hash`).
    pub const SOL_AUDIT: Self = Self(0x0509);
    /// BTC 받는 주소.
    pub const BTC_TO: Self = Self(0x0601);
    /// BTC 주소 종류.
    pub const BTC_TYPE: Self = Self(0x0602);
    /// BTC 금액.
    pub const BTC_AMOUNT: Self = Self(0x0603);
    /// BTC 잔돈.
    pub const BTC_CHANGE: Self = Self(0x0604);
    /// BTC 입력.
    pub const BTC_INPUTS: Self = Self(0x0605);
    /// BTC 수수료.
    pub const BTC_FEE: Self = Self(0x0606);
    /// BTC 총 차감.
    pub const BTC_TOTAL: Self = Self(0x0607);
    /// BTC 승인 후 잔액.
    pub const BTC_BALANCE: Self = Self(0x0608);
    /// BTC 교체 대상(`BtcFeeBump`만).
    pub const BTC_REPLACES: Self = Self(0x0609);
    /// BTC 고급(version·nLockTime·RBF·vsize·weight·txid).
    pub const BTC_ADVANCED: Self = Self(0x0640);

    /// `(critical, volatile)` for keys of the §11.2 table; `None` for unknown keys.
    #[must_use]
    pub const fn flags(self) -> Option<(bool, bool)> {
        Some(match self.0 {
            0x0001..=0x0003
            | 0x0101..=0x0104
            | 0x0110..=0x0112
            | 0x0120
            | 0x0125
            | 0x0301..=0x0304
            | 0x0401
            | 0x0402
            | 0x0404..=0x0406
            | 0x0501..=0x0505
            | 0x0601..=0x0607
            | 0x0609 => (true, false),
            0x0121 | 0x0130 => (false, true),
            0x0113
            | 0x0122..=0x0124
            | 0x0140
            | 0x0141
            | 0x0403
            | 0x0506..=0x0509
            | 0x0608
            | 0x0640 => (false, false),
            _ => return None,
        })
    }
}

/// Display validation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayError {
    /// Unknown field key.
    UnknownKey(u16),
    /// A string breaks the display-character rules or a size bound.
    InvalidText,
    /// Too many fields or warnings.
    TooMany,
}

impl fmt::Display for DisplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownKey(_) => "unknown display field key",
            Self::InvalidText => "invalid display text",
            Self::TooMany => "too many display entries",
        })
    }
}

impl std::error::Error for DisplayError {}

/// One display field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayField {
    /// Key.
    pub key: FieldKey,
    /// Sub-label (argument name, path, item), possibly empty.
    pub sub_label: String,
    /// Value.
    pub value: String,
    /// Shown unfolded.
    pub critical: bool,
    /// May change on re-simulation without re-approval.
    pub volatile: bool,
}

impl DisplayField {
    /// Builds a field; flags come from the key table and strings are re-checked.
    ///
    /// # Errors
    ///
    /// [`DisplayError::UnknownKey`] or [`DisplayError::InvalidText`].
    pub fn new(
        key: FieldKey,
        sub_label: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, DisplayError> {
        let (critical, volatile) = key.flags().ok_or(DisplayError::UnknownKey(key.0))?;
        let field = Self {
            key,
            sub_label: sub_label.into(),
            value: value.into(),
            critical,
            volatile,
        };
        field.validate()?;
        Ok(field)
    }

    fn validate(&self) -> Result<(), DisplayError> {
        let flags = self
            .key
            .flags()
            .ok_or(DisplayError::UnknownKey(self.key.0))?;
        if flags != (self.critical, self.volatile)
            || !is_valid_display_text(&self.sub_label, MAX_SUB_LABEL_BYTES, true)
            || !is_valid_display_text(&self.value, MAX_DISPLAY_VALUE_BYTES, false)
        {
            return Err(DisplayError::InvalidText);
        }
        Ok(())
    }
}

/// The approval display (spec/03 §11.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalDisplay {
    /// `[{network}] {action}`.
    pub title: String,
    /// Fields in display order.
    pub fields: Vec<DisplayField>,
    /// Warnings in §10.1 order.
    pub warnings: Vec<Warning>,
    /// Request level.
    pub risk: RiskLevel,
    /// `risk == High`.
    pub ack_required: bool,
}

impl ApprovalDisplay {
    /// Sorts the warnings, derives the level and validates every string.
    ///
    /// # Errors
    ///
    /// [`DisplayError`] when a bound or a character rule is violated.
    pub fn new(
        title: String,
        fields: Vec<DisplayField>,
        mut warnings: Vec<Warning>,
    ) -> Result<Self, DisplayError> {
        sort_warnings(&mut warnings);
        let (risk, ack_required) = request_risk(&warnings);
        let display = Self {
            title,
            fields,
            warnings,
            risk,
            ack_required,
        };
        display.validate()?;
        Ok(display)
    }

    /// Re-checks every rule (`DisplayField::new` rules, counts, title, warning texts).
    ///
    /// # Errors
    ///
    /// [`DisplayError`].
    pub fn validate(&self) -> Result<(), DisplayError> {
        if self.fields.len() > MAX_DISPLAY_FIELDS || self.warnings.len() > MAX_DISPLAY_WARNINGS {
            return Err(DisplayError::TooMany);
        }
        if !is_valid_display_text(&self.title, MAX_TITLE_BYTES, false) {
            return Err(DisplayError::InvalidText);
        }
        for field in &self.fields {
            field.validate()?;
        }
        for warning in &self.warnings {
            if !is_valid_display_text(&warning.text, MAX_DISPLAY_VALUE_BYTES, false) {
                return Err(DisplayError::InvalidText);
            }
        }
        Ok(())
    }

    fn encode(&self, include_volatile: bool) -> Result<Vec<u8>, DisplayError> {
        self.validate()?;
        let length = |text: &str| u32::try_from(text.len()).map_err(|_| DisplayError::InvalidText);
        let fields: Vec<&DisplayField> = self
            .fields
            .iter()
            .filter(|field| include_volatile || !field.volatile)
            .collect();
        let mut out = Vec::new();
        out.extend_from_slice(DISPLAY_MAGIC);
        out.extend_from_slice(&1_u16.to_be_bytes());
        out.push(self.risk.code());
        out.push(u8::from(self.ack_required));
        out.extend_from_slice(&length(&self.title)?.to_be_bytes());
        out.extend_from_slice(self.title.as_bytes());
        let count = u16::try_from(fields.len()).map_err(|_| DisplayError::TooMany)?;
        out.extend_from_slice(&count.to_be_bytes());
        for field in fields {
            out.extend_from_slice(&field.key.0.to_be_bytes());
            out.push(u8::from(field.critical) | (u8::from(field.volatile) << 1));
            out.extend_from_slice(&length(&field.sub_label)?.to_be_bytes());
            out.extend_from_slice(field.sub_label.as_bytes());
            out.extend_from_slice(&length(&field.value)?.to_be_bytes());
            out.extend_from_slice(field.value.as_bytes());
        }
        let count = u16::try_from(self.warnings.len()).map_err(|_| DisplayError::TooMany)?;
        out.extend_from_slice(&count.to_be_bytes());
        for warning in &self.warnings {
            out.extend_from_slice(&warning.rule.0.to_be_bytes());
            out.push(warning.level.code());
            out.extend_from_slice(&length(&warning.text)?.to_be_bytes());
            out.extend_from_slice(warning.text.as_bytes());
        }
        Ok(out)
    }

    /// Canonical display bytes (`YWDSP003…`, spec/03 §11.3).
    ///
    /// # Errors
    ///
    /// [`DisplayError`] when the display is invalid.
    pub fn bytes(&self) -> Result<Vec<u8>, DisplayError> {
        self.encode(true)
    }

    /// The same encoding without volatile fields (stable-part comparison, spec/03 §6.6).
    ///
    /// # Errors
    ///
    /// [`DisplayError`] when the display is invalid.
    pub fn stable_bytes(&self) -> Result<Vec<u8>, DisplayError> {
        self.encode(false)
    }

    /// `SHA-256(Transcript("your-wallet/v3/display", 1).push_bytes(display_bytes))`.
    ///
    /// # Errors
    ///
    /// [`DisplayError`] when the display is invalid.
    pub fn digest(&self) -> Result<[u8; 32], DisplayError> {
        let bytes = self.bytes()?;
        let mut transcript =
            Transcript::start_domain(DISPLAY_DOMAIN, 1).map_err(|_| DisplayError::TooMany)?;
        transcript
            .push_bytes(&bytes)
            .map_err(|_| DisplayError::TooMany)?;
        Ok(Sha256::digest(transcript.as_bytes()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::{ApprovalDisplay, DisplayError, DisplayField, FieldKey};
    use crate::approval::{RiskLevel, Warning};
    use crate::evm::risk::{E01, E12, E28, E31, warning};

    #[test]
    fn field_flags_and_validation() {
        let field = DisplayField::new(FieldKey::EXPECTED_FEE, "", "알 수 없음").unwrap();
        assert!(!field.critical && field.volatile);
        assert!(DisplayField::new(FieldKey::TO, "", "x").unwrap().critical);
        assert_eq!(
            DisplayField::new(FieldKey(0x0999), "", "x"),
            Err(DisplayError::UnknownKey(0x0999))
        );
        assert_eq!(
            DisplayField::new(FieldKey::MESSAGE_TEXT, "", "a\u{202E}"),
            Err(DisplayError::InvalidText)
        );
        assert_eq!(
            DisplayField::new(FieldKey::MESSAGE_TEXT, "", " a"),
            Err(DisplayError::InvalidText)
        );
        assert!(DisplayField::new(FieldKey::MESSAGE_TEXT, "", "a\nb").is_ok());
        assert!(DisplayField::new(FieldKey::MESSAGE_TEXT, "", "x".repeat(270_000)).is_ok());
        assert!(DisplayField::new(FieldKey::MESSAGE_TEXT, "", "x".repeat(270_001)).is_err());
    }

    #[test]
    fn warning_order_and_risk() {
        let display = ApprovalDisplay::new(
            "[t] x".to_owned(),
            Vec::new(),
            vec![
                warning(E28, None),
                warning(E12, None),
                warning(E31, None),
                warning(E01, Some("원인")),
            ],
        )
        .unwrap();
        let rules: Vec<_> = display.warnings.iter().map(|w| w.rule).collect();
        assert_eq!(rules, vec![E01, E12, E28, E31]);
        assert_eq!(display.risk, RiskLevel::High);
        assert!(display.ack_required);
        let empty = ApprovalDisplay::new("[t] x".to_owned(), Vec::new(), Vec::new()).unwrap();
        assert_eq!(empty.risk, RiskLevel::Info);
        assert!(!empty.ack_required);
        let bad = ApprovalDisplay::new(
            "[t] x".to_owned(),
            Vec::new(),
            vec![Warning {
                rule: E28,
                level: RiskLevel::Info,
                text: "a\u{200B}".to_owned(),
            }],
        );
        assert_eq!(bad, Err(DisplayError::InvalidText));
    }

    #[test]
    fn stable_bytes_drop_volatile_fields() {
        let fields = vec![
            DisplayField::new(FieldKey::TO, "", "a").unwrap(),
            DisplayField::new(FieldKey::EXPECTED_FEE, "", "1 ETH").unwrap(),
        ];
        let display = ApprovalDisplay::new("[t] x".to_owned(), fields, Vec::new()).unwrap();
        let mut changed = display.clone();
        changed.fields.get_mut(1).unwrap().value = "2 ETH".to_owned();
        assert_ne!(display.bytes().unwrap(), changed.bytes().unwrap());
        assert_eq!(
            display.stable_bytes().unwrap(),
            changed.stable_bytes().unwrap()
        );
        assert_ne!(display.digest().unwrap(), changed.digest().unwrap());
    }
}
