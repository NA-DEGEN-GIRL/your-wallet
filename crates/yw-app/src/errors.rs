//! User-visible error codes and fixed Korean messages (spec/04 §7). Remote or OS strings are never
//! shown; every failure is classified into an [`ErrorCode`] and displayed as `"<문구> (<코드>)"`.

use yw_core::error::{KeyError, StorageError, VaultError};

/// A classified error (spec/04 §7 table).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// `settings.json` unreadable or invalid key.
    App001,
    /// `settings.json` / `apikeys.dpapi` write failure.
    App002,
    /// Session notification registration failed.
    App004,
    /// Event queue full.
    App005,
    /// Internal error.
    App009,
    /// Pipe creation failed.
    Pipe001,
    /// `UnlockFailed`.
    Vlt001,
    /// Malformed / unsupported vault.
    Vlt002,
    /// Vault storage failure.
    Vlt003,
    /// Randomness unavailable.
    Vlt005,
    /// Sidecar corrupt.
    Vlt006,
    /// `VirtualLock` / out of memory.
    Vlt007,
    /// Payload corrupt.
    Vlt008,
    /// Backup not confirmed.
    Vlt009,
    /// Raw key limit.
    Vlt010,
    /// Duplicate raw key.
    Vlt011,
    /// Password rule.
    Inp001,
    /// Confirmation mismatch.
    Inp002,
    /// Mnemonic word count.
    Inp003,
    /// Unknown mnemonic word (position in the message).
    Inp004,
    /// Mnemonic checksum / format.
    Inp005,
    /// Private key format.
    Inp006,
    /// Invalid private key.
    Inp007,
    /// Non-ASCII / IME.
    Inp008,
    /// Backup mismatch.
    Inp013,
    /// Label rule.
    Inp017,
    /// Paste rejected.
    Inp018,
    /// Passphrase rule.
    Inp019,
    /// Capture exclusion failed on a display window.
    Sec001,
    /// Clipboard unavailable.
    Sec002,
    /// `apikeys.dpapi` unreadable.
    Key001,
    /// Template credential format.
    Key002,
    /// RPC URL format.
    Key003,
    /// Template credential missing.
    Key004,
    /// No endpoint for the network.
    Key005,
    /// DNS / connect failure.
    Rpc001,
    /// Timeout.
    Rpc002,
    /// HTTP 401/403.
    Rpc003,
    /// HTTP 429.
    Rpc004,
    /// Malformed response.
    Rpc005,
    /// Wrong network.
    Rpc006,
    /// Other JSON-RPC error.
    Rpc007,
    /// TLS failure.
    Rpc008,
    /// Referrer / origin allowlist.
    Rpc009,
    /// Endpoint test mismatch.
    Rpc010,
    /// Address format.
    Inp009,
    /// EIP-55 checksum mismatch.
    Inp010,
    /// Amount format.
    Inp011,
    /// Insufficient balance (fee included).
    Inp012,
    /// Zero address.
    Inp014,
    /// Recipient is the token contract.
    Inp015,
    /// Address-book duplicate.
    Inp016,
    /// Simulation reverted (band).
    Sim001,
    /// No simulation result (band).
    Sim002,
    /// Simulation unsupported (band).
    Sim003,
    /// Simulation incomplete (band).
    Sim004,
    /// Chain add: RPC chain id differs.
    Chn001,
    /// Chain add: RPC unreachable.
    Chn002,
    /// Chain id already registered.
    Chn003,
    /// Chain input format.
    Chn004,
    /// Chain name duplicate.
    Chn005,
    /// More than 32 user chains.
    Chn006,
    /// Delete refused: open transactions or approvals.
    Chn007,
    /// Pinned genesis mismatch.
    Chn008,
    /// Delete refused: active chain.
    Chn009,
    /// Chain add: no EIP-1559 base fee.
    Chn010,
    /// Fee cap exceeded (E05).
    Tx001,
    /// Transaction in flight (E06).
    Tx002,
    /// Post-sign verification failed.
    Tx003,
    /// Broadcast result unknown.
    Tx004,
    /// Journal full.
    Tx005,
    /// Display validation failure.
    Ui001,
}

impl ErrorCode {
    /// `"E-XXX-nnn"`.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::App001 => "E-APP-001",
            Self::App002 => "E-APP-002",
            Self::App004 => "E-APP-004",
            Self::App005 => "E-APP-005",
            Self::App009 => "E-APP-009",
            Self::Pipe001 => "E-PIPE-001",
            Self::Vlt001 => "E-VLT-001",
            Self::Vlt002 => "E-VLT-002",
            Self::Vlt003 => "E-VLT-003",
            Self::Vlt005 => "E-VLT-005",
            Self::Vlt006 => "E-VLT-006",
            Self::Vlt007 => "E-VLT-007",
            Self::Vlt008 => "E-VLT-008",
            Self::Vlt009 => "E-VLT-009",
            Self::Vlt010 => "E-VLT-010",
            Self::Vlt011 => "E-VLT-011",
            Self::Inp001 => "E-INP-001",
            Self::Inp002 => "E-INP-002",
            Self::Inp003 => "E-INP-003",
            Self::Inp004 => "E-INP-004",
            Self::Inp005 => "E-INP-005",
            Self::Inp006 => "E-INP-006",
            Self::Inp007 => "E-INP-007",
            Self::Inp008 => "E-INP-008",
            Self::Inp013 => "E-INP-013",
            Self::Inp017 => "E-INP-017",
            Self::Inp018 => "E-INP-018",
            Self::Inp019 => "E-INP-019",
            Self::Sec001 => "E-SEC-001",
            Self::Sec002 => "E-SEC-002",
            Self::Key001 => "E-KEY-001",
            Self::Key002 => "E-KEY-002",
            Self::Key003 => "E-KEY-003",
            Self::Key004 => "E-KEY-004",
            Self::Key005 => "E-KEY-005",
            Self::Rpc001 => "E-RPC-001",
            Self::Rpc002 => "E-RPC-002",
            Self::Rpc003 => "E-RPC-003",
            Self::Rpc004 => "E-RPC-004",
            Self::Rpc005 => "E-RPC-005",
            Self::Rpc006 => "E-RPC-006",
            Self::Rpc007 => "E-RPC-007",
            Self::Rpc008 => "E-RPC-008",
            Self::Rpc009 => "E-RPC-009",
            Self::Rpc010 => "E-RPC-010",
            Self::Inp009 => "E-INP-009",
            Self::Inp010 => "E-INP-010",
            Self::Inp011 => "E-INP-011",
            Self::Inp012 => "E-INP-012",
            Self::Inp014 => "E-INP-014",
            Self::Inp015 => "E-INP-015",
            Self::Inp016 => "E-INP-016",
            Self::Sim001 => "E-SIM-001",
            Self::Sim002 => "E-SIM-002",
            Self::Sim003 => "E-SIM-003",
            Self::Sim004 => "E-SIM-004",
            Self::Chn001 => "E-CHN-001",
            Self::Chn002 => "E-CHN-002",
            Self::Chn003 => "E-CHN-003",
            Self::Chn004 => "E-CHN-004",
            Self::Chn005 => "E-CHN-005",
            Self::Chn006 => "E-CHN-006",
            Self::Chn007 => "E-CHN-007",
            Self::Chn008 => "E-CHN-008",
            Self::Chn009 => "E-CHN-009",
            Self::Chn010 => "E-CHN-010",
            Self::Tx001 => "E-TX-001",
            Self::Tx002 => "E-TX-002",
            Self::Tx003 => "E-TX-003",
            Self::Tx004 => "E-TX-004",
            Self::Tx005 => "E-TX-005",
            Self::Ui001 => "E-UI-001",
        }
    }

    /// The fixed Korean sentence (without the code). `{n}`/`{키}`-style parts are filled by
    /// [`ErrorCode::render`].
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::App001 => "설정 파일을 읽지 못해 기본값을 사용합니다.",
            Self::App002 => "설정을 저장하지 못했습니다. 디스크 공간과 권한을 확인하세요.",
            Self::App004 => "Windows 잠금 감지를 켜지 못했습니다. 자리를 비울 때 직접 잠그세요.",
            Self::App005 => "요청이 너무 많아 일부를 처리하지 못했습니다.",
            Self::App009 => "내부 오류가 발생했습니다. 로그를 확인하세요.",
            Self::Pipe001 => "브라우저 연결을 시작하지 못했습니다. 앱을 다시 실행하세요.",
            Self::Vlt001 => "비밀번호가 올바르지 않거나 vault 파일이 손상되었습니다.",
            Self::Vlt002 => "지갑 파일을 읽을 수 없습니다. 손상되었거나 다른 버전의 파일입니다.",
            Self::Vlt003 => "지갑 파일을 저장하지 못했습니다. 디스크 공간과 권한을 확인하세요.",
            Self::Vlt005 => "안전한 난수를 얻지 못해 작업을 중단했습니다.",
            Self::Vlt006 => "지갑 부가 파일(meta·저널)을 읽을 수 없습니다.",
            Self::Vlt007 => "메모리를 잠그지 못해 잠금 해제하지 않았습니다.",
            Self::Vlt008 => "지갑 내용이 손상되었습니다. 이전 사본(.prev)으로 복구할 수 있습니다.",
            Self::Vlt009 => "백업 확인을 먼저 끝내세요.",
            Self::Vlt010 => "가져온 개인키는 최대 15개입니다.",
            Self::Vlt011 => "이미 가져온 개인키입니다.",
            Self::Inp001 => "비밀번호는 영문·숫자·기호(ASCII) 12–128자여야 합니다.",
            Self::Inp002 => "두 입력이 다릅니다.",
            Self::Inp003 => "단어 수는 12, 15, 18, 21, 24 중 하나여야 합니다.",
            Self::Inp004 => "{n}번째 단어가 BIP39 영어 단어 목록에 없습니다.",
            Self::Inp005 => "니모닉이 올바르지 않습니다. 단어 철자와 순서를 확인하세요.",
            Self::Inp006 => "개인키는 16진수 64자리여야 합니다.",
            Self::Inp007 => "사용할 수 없는 개인키입니다.",
            Self::Inp008 => "영문(ASCII)만 입력할 수 있습니다. 한/영 키로 영문 입력으로 바꾸세요.",
            Self::Inp013 => "입력한 단어 또는 주소가 맞지 않습니다.",
            Self::Inp017 => {
                "이름은 1–32자이고 앞뒤 공백·제어 문자·보이지 않는 문자를 쓸 수 없습니다."
            }
            Self::Inp018 => "붙여넣은 내용에 허용되지 않는 문자가 있거나 너무 깁니다.",
            Self::Inp019 => "passphrase는 영문·숫자·기호(ASCII) 1–256자여야 합니다.",
            Self::Sec001 => "화면 캡처 제외를 적용하지 못해 표시하지 않습니다.",
            Self::Sec002 => "클립보드를 사용할 수 없습니다. 잠시 후 다시 시도하세요.",
            Self::Key001 => "저장된 RPC 엔드포인트·API 키를 읽을 수 없습니다. 다시 입력하세요.",
            Self::Key002 => "공급자 템플릿 입력 형식이 올바르지 않습니다.",
            Self::Key003 => "RPC URL은 https:// 로 시작하는 올바른 주소여야 합니다.",
            Self::Key004 => {
                "선택한 RPC 공급자 템플릿의 자격 정보가 없습니다. 설정 → RPC 공급자에서 먼저 저장하세요."
            }
            Self::Key005 => {
                "RPC 엔드포인트가 없습니다. 설정 → 네트워크 URL에서 이 네트워크의 URL을 만들거나 입력하세요."
            }
            Self::Rpc001 => "네트워크에 연결할 수 없습니다.",
            Self::Rpc002 => "RPC 응답 시간이 초과되었습니다.",
            Self::Rpc003 => {
                "RPC 엔드포인트가 인증을 거부했습니다. 설정 → 네트워크 URL에서 이 네트워크의 URL(토큰)을 확인하세요."
            }
            Self::Rpc004 => "요청 한도를 넘었습니다. 잠시 후 다시 시도하세요.",
            Self::Rpc005 => "RPC 응답 형식이 올바르지 않습니다.",
            Self::Rpc006 => "RPC가 다른 네트워크를 가리킵니다. 작업을 중단했습니다.",
            Self::Rpc007 => "RPC가 요청을 거부했습니다.",
            Self::Rpc008 => "보안 연결(TLS)을 맺지 못했습니다.",
            Self::Rpc009 => {
                "RPC 엔드포인트에 리퍼러·도메인 허용 목록이 걸려 있습니다. 공급자 대시보드에서 해제하세요(토큰 인증·IP 허용 목록은 무방, D13)."
            }
            Self::Rpc010 => "엔드포인트 테스트 실패: {항목} 불일치 — 다른 네트워크의 URL입니다.",
            Self::Inp009 => "주소 형식이 올바르지 않습니다.",
            Self::Inp010 => "주소의 대소문자 체크섬이 맞지 않습니다. 주소를 다시 확인하세요.",
            Self::Inp011 => "금액 형식이 올바르지 않습니다.",
            Self::Inp012 => "잔액이 부족합니다(수수료 포함).",
            Self::Inp014 => "0 주소로는 보낼 수 없습니다.",
            Self::Inp015 => "받는 주소가 이 토큰의 컨트랙트입니다. 보내면 잃습니다.",
            Self::Inp016 => "이미 주소록에 있는 주소입니다.",
            Self::Sim001 => "시뮬레이션에서 거래가 실패했습니다 — 수수료만 잃을 수 있습니다",
            Self::Sim002 => "시뮬레이션 결과 없음 — 실제 효과를 확인할 수 없습니다",
            Self::Sim003 => "시뮬레이션 미지원 체인 — 실제 효과를 확인할 수 없습니다",
            Self::Sim004 => "시뮬레이션 결과 불완전 — 일부 효과를 확인할 수 없습니다",
            Self::Chn001 => "RPC의 chainId({n})가 입력한 chainId와 다릅니다.",
            Self::Chn002 => "RPC에 연결하지 못해 체인을 확인할 수 없습니다.",
            Self::Chn003 => "이미 등록된 chainId입니다.",
            Self::Chn004 => "{항목} 형식이 올바르지 않습니다.",
            Self::Chn005 => "같은 이름의 체인이 이미 있습니다.",
            Self::Chn006 => "사용자 체인은 최대 32개입니다.",
            Self::Chn007 => {
                "진행 중인 거래나 승인 대기가 있는 체인은 삭제할 수 없습니다. 확정된 뒤 다시 시도하세요."
            }
            Self::Chn008 => "체인 정보가 바뀌었습니다 (제네시스 불일치)",
            Self::Chn009 => "사용 중인 체인은 삭제할 수 없습니다. 네트워크를 먼저 바꾸세요.",
            Self::Chn010 => "EIP-1559를 지원하지 않는 체인입니다.",
            Self::Tx001 => "수수료가 설정한 상한을 넘습니다.",
            Self::Tx002 => "이 계정의 이전 거래가 아직 확정되지 않았습니다.",
            Self::Tx003 => "내부 검증에 실패해 거래를 보내지 않았습니다.",
            Self::Tx004 => "전송 결과를 확인할 수 없습니다. 활동에서 상태를 확인하세요.",
            Self::Tx005 => "거래 저널 공간이 부족합니다.",
            Self::Ui001 => "요청 내용을 안전하게 표시할 수 없어 거부했습니다.",
        }
    }

    /// `"<message> (<code>)"`.
    #[must_use]
    pub fn text(self) -> String {
        format!("{} ({})", self.message(), self.code())
    }

    /// Like [`ErrorCode::text`] with one `{…}` placeholder replaced by `value`.
    #[must_use]
    pub fn render(self, value: &str) -> String {
        let message = self.message();
        let filled = match (message.find('{'), message.find('}')) {
            (Some(open), Some(close)) if open < close => {
                let (head, rest) = message.split_at(open);
                let tail = rest
                    .get(close.saturating_sub(open).saturating_add(1)..)
                    .unwrap_or("");
                format!("{head}{value}{tail}")
            }
            _ => message.to_owned(),
        };
        format!("{filled} ({})", self.code())
    }
}

/// Classifies a vault error (spec/04 §7 "분류 입력").
#[must_use]
pub const fn vault_code(error: VaultError) -> ErrorCode {
    match error {
        VaultError::UnlockFailed => ErrorCode::Vlt001,
        VaultError::Malformed | VaultError::UnsupportedVersion | VaultError::UnsupportedParams => {
            ErrorCode::Vlt002
        }
        VaultError::Storage(_) => ErrorCode::Vlt003,
        VaultError::SidecarCorrupt(_) | VaultError::SidecarVaultMismatch(_) => ErrorCode::Vlt006,
        VaultError::OutOfMemory => ErrorCode::Vlt007,
        VaultError::PayloadCorrupt => ErrorCode::Vlt008,
        VaultError::BackupNotConfirmed => ErrorCode::Vlt009,
        VaultError::BackupMismatch | VaultError::ChallengeStale => ErrorCode::Inp013,
        VaultError::RecordLimit => ErrorCode::Vlt010,
        VaultError::DuplicateKey => ErrorCode::Vlt011,
        VaultError::Key(key) => key_code(key),
        VaultError::InvalidState | VaultError::RecordNotFound => ErrorCode::App009,
    }
}

/// Classifies a key error.
#[must_use]
pub const fn key_code(error: KeyError) -> ErrorCode {
    match error {
        KeyError::RandomnessUnavailable => ErrorCode::Vlt005,
        KeyError::PasswordTooShort | KeyError::PasswordTooLong | KeyError::PasswordInvalidChar => {
            ErrorCode::Inp001
        }
        KeyError::PassphraseTooLong
        | KeyError::PassphraseInvalidChar
        | KeyError::PassphraseEmpty => ErrorCode::Inp019,
        KeyError::MnemonicWordCount => ErrorCode::Inp003,
        KeyError::MnemonicUnknownWord { .. } => ErrorCode::Inp004,
        KeyError::MnemonicFormat | KeyError::MnemonicChecksum => ErrorCode::Inp005,
        KeyError::InvalidPrivateKey => ErrorCode::Inp007,
        KeyError::InvalidEntropyLength
        | KeyError::InvalidPath
        | KeyError::InvalidAccountIndex
        | KeyError::DerivationFailed
        | KeyError::InvalidExtendedKey
        | KeyError::Internal => ErrorCode::App009,
    }
}

/// `StorageError` name for logs (no paths).
#[must_use]
pub const fn storage_name(error: StorageError) -> &'static str {
    match error {
        StorageError::NotFound => "NotFound",
        StorageError::AlreadyExists => "AlreadyExists",
        StorageError::GenerationConflict => "GenerationConflict",
        StorageError::Corrupt => "Corrupt",
        StorageError::TooLarge => "TooLarge",
        StorageError::Io(_) => "Io",
    }
}

#[cfg(test)]
mod tests {
    use super::{ErrorCode, vault_code};
    use yw_core::error::{KeyError, VaultError};

    #[test]
    fn rendering_fills_one_placeholder_and_appends_code() {
        assert_eq!(
            ErrorCode::Inp004.render("3"),
            "3번째 단어가 BIP39 영어 단어 목록에 없습니다. (E-INP-004)"
        );
        assert_eq!(
            ErrorCode::Rpc010.render("chainId"),
            "엔드포인트 테스트 실패: chainId 불일치 — 다른 네트워크의 URL입니다. (E-RPC-010)"
        );
        assert_eq!(
            ErrorCode::Vlt001.text(),
            "비밀번호가 올바르지 않거나 vault 파일이 손상되었습니다. (E-VLT-001)"
        );
    }

    #[test]
    fn unlock_failure_and_tamper_share_one_code() {
        assert_eq!(vault_code(VaultError::UnlockFailed), ErrorCode::Vlt001);
        assert_eq!(
            vault_code(VaultError::Key(KeyError::MnemonicUnknownWord {
                position: 2
            })),
            ErrorCode::Inp004
        );
        assert_eq!(vault_code(VaultError::OutOfMemory), ErrorCode::Vlt007);
    }
}
