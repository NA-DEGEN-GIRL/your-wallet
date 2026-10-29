//! Error enums with manual `Display` (spec/01 §5.2, spec/02 §10.2).
//!
//! Error values never carry secrets. `Display` uses only the fixed Korean sentences of the
//! spec/04 §7 table (without the `(E-…)` code, which yw-app appends); logs record only the
//! variant name (D28).

use core::fmt;

use crate::vault::FileKind;

const INTERNAL: &str = "내부 오류가 발생했습니다. 로그를 확인하세요.";

/// Key, mnemonic, password and derivation errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The OS CSPRNG failed or returned stuck output; the operation was aborted.
    RandomnessUnavailable,
    /// Vault password shorter than 12 bytes.
    PasswordTooShort,
    /// Vault password longer than 128 bytes.
    PasswordTooLong,
    /// Vault password byte outside 0x20–0x7E.
    PasswordInvalidChar,
    /// BIP39 passphrase longer than 256 bytes.
    PassphraseTooLong,
    /// BIP39 passphrase byte outside 0x20–0x7E.
    PassphraseInvalidChar,
    /// An empty passphrase where a non-empty one is required.
    PassphraseEmpty,
    /// Mnemonic text violates the strict format (length, characters or spacing).
    MnemonicFormat,
    /// Mnemonic word count is not 12, 15, 18, 21 or 24.
    MnemonicWordCount,
    /// A word is not in the BIP39 English list (1-based position of the first one).
    MnemonicUnknownWord {
        /// 1-based position of the first unknown word.
        position: u8,
    },
    /// Mnemonic checksum mismatch.
    MnemonicChecksum,
    /// Entropy or seed length is not supported.
    InvalidEntropyLength,
    /// Derivation path is malformed or out of range.
    InvalidPath,
    /// Account index above `MAX_ACCOUNT_INDEX`.
    InvalidAccountIndex,
    /// The key at this path cannot be derived (IL ≥ n or a zero child key).
    DerivationFailed,
    /// Private key format or range is invalid.
    InvalidPrivateKey,
    /// `decode_xkey` rejected the string (test API only).
    InvalidExtendedKey,
    /// A Solana private key is neither a base58 64-byte keypair nor a JSON array of 64 numbers
    /// (spec/02 §8.4).
    SolKeyFormat,
    /// The Solana key text decodes to 32 bytes: most likely an address, not a private key.
    SolKeyIsAddress,
    /// The public half of a Solana keypair is not the public key of its secret half.
    SolKeyMismatch,
    /// A Bitcoin WIF is malformed (length, characters, checksum, version, suffix or range).
    WifFormat,
    /// An uncompressed WIF key was paired with a script type other than P2PKH.
    WifUncompressedScript,
    /// A library returned an unexpected error, or the word list failed to load.
    Internal,
}

impl fmt::Display for KeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomnessUnavailable => {
                formatter.write_str("안전한 난수를 얻지 못해 작업을 중단했습니다.")
            }
            Self::PasswordTooShort | Self::PasswordTooLong | Self::PasswordInvalidChar => {
                formatter.write_str("비밀번호는 영문·숫자·기호(ASCII) 12–128자여야 합니다.")
            }
            Self::PassphraseTooLong | Self::PassphraseInvalidChar | Self::PassphraseEmpty => {
                formatter.write_str("passphrase는 영문·숫자·기호(ASCII) 1–256자여야 합니다.")
            }
            Self::MnemonicFormat | Self::MnemonicChecksum => {
                formatter.write_str("니모닉이 올바르지 않습니다. 단어 철자와 순서를 확인하세요.")
            }
            Self::MnemonicWordCount => {
                formatter.write_str("단어 수는 12, 15, 18, 21, 24 중 하나여야 합니다.")
            }
            Self::MnemonicUnknownWord { position } => {
                write!(
                    formatter,
                    "{position}번째 단어가 BIP39 영어 단어 목록에 없습니다."
                )
            }
            Self::DerivationFailed => formatter.write_str("이 경로에서 키를 파생할 수 없습니다."),
            Self::InvalidPrivateKey => formatter.write_str("사용할 수 없는 개인키입니다."),
            Self::SolKeyFormat => formatter.write_str(
                "Solana 개인키는 base58 64바이트 keypair(Phantom·Solflare 내보내기) 또는 숫자 64개의 JSON 배열(solana-keygen 파일)이어야 합니다.",
            ),
            Self::SolKeyIsAddress => formatter.write_str(
                "입력한 값은 32바이트라 개인키가 아니라 Solana 주소(공개키)로 보입니다. 지갑의 '개인키 내보내기'로 받은 값을 넣으세요.",
            ),
            Self::SolKeyMismatch => formatter.write_str(
                "keypair의 공개키 부분이 개인키와 맞지 않습니다. 값이 잘리거나 바뀌지 않았는지 확인하세요.",
            ),
            Self::WifFormat => formatter.write_str(
                "Bitcoin 개인키는 WIF(5·K·L·9·c로 시작하는 base58 51–52자)여야 합니다. 글자와 체크섬을 확인하세요.",
            ),
            Self::WifUncompressedScript => formatter.write_str(
                "압축되지 않은 키(5·9로 시작하는 WIF)는 P2PKH(레거시) 주소에만 쓸 수 있습니다.",
            ),
            Self::InvalidEntropyLength
            | Self::InvalidPath
            | Self::InvalidAccountIndex
            | Self::InvalidExtendedKey
            | Self::Internal => formatter.write_str(INTERNAL),
        }
    }
}

impl std::error::Error for KeyError {}

/// Storage contract errors (spec/02 §6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageError {
    /// The file does not exist.
    NotFound,
    /// `commit(…, None, …)` but the main file exists.
    AlreadyExists,
    /// The main file generation differs from the expected one.
    GenerationConflict,
    /// The main file cannot be parsed to check its generation.
    Corrupt,
    /// The file exceeds its size bound.
    TooLarge,
    /// An OS error code.
    Io(u32),
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("지갑 파일을 저장하지 못했습니다. 디스크 공간과 권한을 확인하세요.")
    }
}

impl std::error::Error for StorageError {}

/// Vault errors (spec/02 §10.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultError {
    /// A key-level error.
    Key(KeyError),
    /// A storage error.
    Storage(StorageError),
    /// The call is not allowed in the current state (or the caller passed invalid input).
    InvalidState,
    /// Structurally malformed vault file.
    Malformed,
    /// Vault version is not 3.
    UnsupportedVersion,
    /// KDF identifier or parameters are not exactly `KDF_V3`.
    UnsupportedParams,
    /// Wrong password or tampered key section (indistinguishable by design).
    UnlockFailed,
    /// The payload failed authentication (AEAD): the file is damaged.
    PayloadCorrupt,
    /// The payload authenticated but does not decode with this build's record set: a newer
    /// build wrote it (spec/02 §4.6, unknown tag). Never offered for `.prev` recovery.
    UnsupportedPayload,
    /// A sidecar file is malformed or failed authentication.
    SidecarCorrupt(FileKind),
    /// A sidecar file belongs to another vault.
    SidecarVaultMismatch(FileKind),
    /// The Argon2 working memory could not be reserved.
    OutOfMemory,
    /// The operation needs a confirmed backup.
    BackupNotConfirmed,
    /// Backup answers do not match.
    BackupMismatch,
    /// The backup challenge is not the current one.
    ChallengeStale,
    /// The vault already holds the maximum number of raw keys.
    RecordLimit,
    /// The raw key is already in the vault.
    DuplicateKey,
    /// No record with this identifier.
    RecordNotFound,
    /// The wallet has no recovery words (a key-only vault, spec/02 §4.6): derivation, the
    /// mnemonic reveal and the BIP39 passphrase do not exist.
    NoMnemonic,
    /// The last key of a key-only vault cannot be removed (a vault holds at least one record).
    LastKey,
}

impl From<KeyError> for VaultError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Key(error) => return error.fmt(formatter),
            Self::Storage(error) => return error.fmt(formatter),
            Self::InvalidState | Self::RecordNotFound => INTERNAL,
            Self::Malformed | Self::UnsupportedVersion | Self::UnsupportedParams => {
                "지갑 파일을 읽을 수 없습니다. 손상되었거나 다른 버전의 파일입니다."
            }
            Self::UnlockFailed => "비밀번호가 올바르지 않거나 vault 파일이 손상되었습니다.",
            Self::PayloadCorrupt => {
                "지갑 내용이 손상되었습니다. 이전 사본(.prev)으로 복구할 수 있습니다."
            }
            Self::UnsupportedPayload => "새 버전 앱이 저장한 지갑입니다. 앱을 업데이트하세요.",
            Self::SidecarCorrupt(_) | Self::SidecarVaultMismatch(_) => {
                "지갑 부가 파일(meta·저널)을 읽을 수 없습니다."
            }
            Self::OutOfMemory => "메모리를 잠그지 못해 잠금 해제하지 않았습니다.",
            Self::BackupNotConfirmed => "백업 확인을 먼저 끝내세요.",
            Self::BackupMismatch => "입력한 단어 또는 주소가 맞지 않습니다.",
            Self::ChallengeStale => "백업 확인 문항이 바뀌었습니다. 새 문항으로 다시 입력하세요.",
            Self::RecordLimit => "가져온 개인키는 체인마다 최대 15개입니다.",
            Self::DuplicateKey => {
                "이미 가져온 개인키이거나, 지갑의 다른 계정과 주소가 같은 키입니다."
            }
            Self::NoMnemonic => "이 지갑에는 복구 단어가 없습니다(개인키로 시작한 지갑).",
            Self::LastKey => "개인키로 시작한 지갑의 마지막 키는 지울 수 없습니다.",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for VaultError {}
