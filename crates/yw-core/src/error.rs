//! Error enums with manual `Display` (spec/01 §5.2, spec/02 §10.2).
//!
//! Error values never carry secrets. The user-facing text is the fixed sentence of the spec/04 §7
//! table (without the `(E-…)` code, which yw-app appends) in the app language (`text_in(lang)`,
//! catalogue [`text`]); `Display` is the Korean text, unchanged (2026-11-14: English added). Logs
//! record only the variant name (D28).

use core::fmt;

use crate::lang::Lang;
use crate::vault::FileKind;

/// The error sentences in both languages (spec/04 §7; 2026-11-14 English added, spec/14).
pub mod text {
    crate::texts! {
        INTERNAL = "내부 오류가 발생했습니다. 로그를 확인하세요."
            / "An internal error occurred. Check the log.";
        RANDOMNESS = "안전한 난수를 얻지 못해 작업을 중단했습니다."
            / "Secure random numbers were unavailable, so the operation was stopped.";
        PASSWORD_RULE = "비밀번호는 영문·숫자·기호(ASCII) 12–128자여야 합니다."
            / "The password must be 12–128 letters, digits or symbols (ASCII).";
        PASSPHRASE_RULE = "passphrase는 영문·숫자·기호(ASCII) 1–256자여야 합니다."
            / "The passphrase must be 1–256 letters, digits or symbols (ASCII).";
        MNEMONIC_INVALID = "니모닉이 올바르지 않습니다. 단어 철자와 순서를 확인하세요."
            / "The recovery words are not valid. Check the spelling and order of the words.";
        WORD_COUNT = "단어 수는 12, 15, 18, 21, 24 중 하나여야 합니다."
            / "The word count must be 12, 15, 18, 21 or 24.";
        UNKNOWN_WORD(1) = "{0}번째 단어가 BIP39 영어 단어 목록에 없습니다."
            / "Word {0} is not in the BIP39 English word list.";
        DERIVATION_FAILED = "이 경로에서 키를 파생할 수 없습니다."
            / "No key can be derived at this path.";
        INVALID_PRIVATE_KEY = "사용할 수 없는 개인키입니다."
            / "This private key cannot be used.";
        SOL_KEY_FORMAT = "Solana 개인키는 base58 64바이트 keypair(Phantom·Solflare 내보내기) 또는 숫자 64개의 JSON 배열(solana-keygen 파일)이어야 합니다."
            / "A Solana private key must be a base58 64-byte keypair (Phantom or Solflare export) or a JSON array of 64 numbers (solana-keygen file).";
        SOL_KEY_IS_ADDRESS = "입력한 값은 32바이트라 개인키가 아니라 Solana 주소(공개키)로 보입니다. 지갑의 '개인키 내보내기'로 받은 값을 넣으세요."
            / "The value is 32 bytes, so it looks like a Solana address (public key), not a private key. Enter the value from your wallet's 'Export private key'.";
        SOL_KEY_MISMATCH = "keypair의 공개키 부분이 개인키와 맞지 않습니다. 값이 잘리거나 바뀌지 않았는지 확인하세요."
            / "The public-key part of the keypair does not match the private key. Check that the value was not cut off or changed.";
        WIF_FORMAT = "Bitcoin 개인키는 WIF(5·K·L·9·c로 시작하는 base58 51–52자)여야 합니다. 글자와 체크섬을 확인하세요."
            / "A Bitcoin private key must be a WIF (base58, 51–52 characters, starting with 5, K, L, 9 or c). Check the characters and the checksum.";
        WIF_UNCOMPRESSED = "압축되지 않은 키(5·9로 시작하는 WIF)는 P2PKH(레거시) 주소에만 쓸 수 있습니다."
            / "An uncompressed key (WIF starting with 5 or 9) can only be used for P2PKH (legacy) addresses.";
        ZEC_KEY_FORMAT = "Zcash 개인키는 압축 WIF(K·L·c로 시작하는 base58 52자) 또는 16진수 64자리여야 합니다. 압축되지 않은 WIF(5·9로 시작)는 받지 않습니다."
            / "A Zcash private key must be a compressed WIF (base58, 52 characters, starting with K, L or c) or 64 hexadecimal characters. Uncompressed WIFs (starting with 5 or 9) are not accepted.";
        ZEC_KEY_NETWORK = "이 WIF는 다른 Zcash 네트워크의 키입니다(K·L = 메인넷, c = 테스트넷). Zcash 탭의 네트워크를 바꾼 뒤 가져오세요."
            / "This WIF is a key for the other Zcash network (K, L = mainnet; c = testnet). Switch the network on the Zcash tab, then import.";
        STORAGE = "지갑 파일을 저장하지 못했습니다. 디스크 공간과 권한을 확인하세요."
            / "The wallet file could not be saved. Check disk space and permissions.";
        VAULT_UNREADABLE = "지갑 파일을 읽을 수 없습니다. 손상되었거나 다른 버전의 파일입니다."
            / "The wallet file cannot be read. It is damaged or from a different version.";
        UNLOCK_FAILED = "비밀번호가 올바르지 않거나 vault 파일이 손상되었습니다."
            / "The password is wrong or the vault file is damaged.";
        PAYLOAD_CORRUPT = "지갑 내용이 손상되었습니다. 이전 사본(.prev)으로 복구할 수 있습니다."
            / "The wallet contents are damaged. You can restore the previous copy (.prev).";
        PAYLOAD_NEWER = "새 버전 앱이 저장한 지갑입니다. 앱을 업데이트하세요."
            / "This wallet was saved by a newer version of the app. Update the app.";
        SIDECAR_UNREADABLE = "지갑 부가 파일(meta·저널)을 읽을 수 없습니다."
            / "The wallet side files (meta, journal) cannot be read.";
        SIDECAR_NEWER = "지갑 부가 파일(meta·저널)이 이 버전이 모르는 형식입니다. 앱을 업데이트하세요."
            / "The wallet side files (meta, journal) are in a format this version does not know. Update the app.";
        OUT_OF_MEMORY = "메모리를 잠그지 못해 잠금 해제하지 않았습니다."
            / "Memory could not be locked, so the wallet was not unlocked.";
        BACKUP_NOT_CONFIRMED = "백업 확인을 먼저 끝내세요."
            / "Finish the backup check first.";
        BACKUP_MISMATCH = "입력한 단어가 맞지 않습니다."
            / "The words you entered do not match.";
        CHALLENGE_STALE = "백업 확인 문항이 바뀌었습니다. 새 문항으로 다시 입력하세요."
            / "The backup check questions have changed. Answer the new questions.";
        RECORD_LIMIT = "가져온 개인키는 체인마다 최대 15개입니다."
            / "You can import at most 15 private keys per chain.";
        DUPLICATE_KEY = "이미 가져온 개인키이거나, 지갑의 다른 계정과 주소가 같은 키입니다."
            / "This private key was already imported, or it has the same address as another account in the wallet.";
        NO_MNEMONIC = "이 지갑에는 복구 단어가 없습니다(개인키로 시작한 지갑)."
            / "This wallet has no recovery words (it was started from a private key).";
        LAST_KEY = "개인키로 시작한 지갑의 마지막 키는 지울 수 없습니다."
            / "The last key of a wallet started from a private key cannot be deleted.";
        PRIMARY_MNEMONIC = "첫 번째 복구 단어는 지울 수 없습니다."
            / "The first recovery words cannot be deleted.";
    }
}

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
    /// A Zcash private key is neither a compressed WIF (`0x80`/`0xEF`) nor 64 hex digits
    /// (spec/12 §2.3).
    ZecKeyFormat,
    /// A Zcash WIF of the other network (mainnet `0x80`, testnet `0xEF`) than the Zcash tab's.
    ZecKeyNetwork,
    /// A library returned an unexpected error, or the word list failed to load.
    Internal,
}

impl KeyError {
    /// The user-facing sentence in `lang` (spec/04 §7, without the code).
    #[must_use]
    pub fn text_in(self, lang: Lang) -> String {
        let text = match self {
            Self::RandomnessUnavailable => text::RANDOMNESS,
            Self::PasswordTooShort | Self::PasswordTooLong | Self::PasswordInvalidChar => {
                text::PASSWORD_RULE
            }
            Self::PassphraseTooLong | Self::PassphraseInvalidChar | Self::PassphraseEmpty => {
                text::PASSPHRASE_RULE
            }
            Self::MnemonicFormat | Self::MnemonicChecksum => text::MNEMONIC_INVALID,
            Self::MnemonicWordCount => text::WORD_COUNT,
            Self::MnemonicUnknownWord { position } => {
                return text::UNKNOWN_WORD.fill(lang, [&position.to_string()]);
            }
            Self::DerivationFailed => text::DERIVATION_FAILED,
            Self::InvalidPrivateKey => text::INVALID_PRIVATE_KEY,
            Self::SolKeyFormat => text::SOL_KEY_FORMAT,
            Self::SolKeyIsAddress => text::SOL_KEY_IS_ADDRESS,
            Self::SolKeyMismatch => text::SOL_KEY_MISMATCH,
            Self::WifFormat => text::WIF_FORMAT,
            Self::WifUncompressedScript => text::WIF_UNCOMPRESSED,
            Self::ZecKeyFormat => text::ZEC_KEY_FORMAT,
            Self::ZecKeyNetwork => text::ZEC_KEY_NETWORK,
            Self::InvalidEntropyLength
            | Self::InvalidPath
            | Self::InvalidAccountIndex
            | Self::InvalidExtendedKey
            | Self::Internal => text::INTERNAL,
        };
        text.get(lang).to_owned()
    }
}

impl fmt::Display for KeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text_in(Lang::Ko))
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

impl StorageError {
    /// The user-facing sentence in `lang` (spec/04 §7 E-VLT-003, without the code).
    #[must_use]
    #[expect(
        clippy::unused_self,
        reason = "every storage error shows the same sentence"
    )]
    pub const fn text_in(self, lang: Lang) -> &'static str {
        text::STORAGE.get(lang)
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.text_in(Lang::Ko))
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
    /// A sidecar authenticated with this vault's key, but its plaintext does not decode with this
    /// build: some build of the app wrote it, almost always a newer one (spec/02 §6.3). Not
    /// damage: nothing is moved or replaced unless the user asks under `고급`.
    SidecarUnsupported(FileKind),
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
    /// The primary (first) recovery phrase cannot be removed (spec/02 §8.6).
    PrimaryMnemonic,
}

impl From<KeyError> for VaultError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

impl VaultError {
    /// The user-facing sentence in `lang` (spec/04 §7, without the code).
    #[must_use]
    pub fn text_in(self, lang: Lang) -> String {
        let text = match self {
            Self::Key(error) => return error.text_in(lang),
            Self::Storage(error) => return error.text_in(lang).to_owned(),
            Self::InvalidState | Self::RecordNotFound => text::INTERNAL,
            Self::Malformed | Self::UnsupportedVersion | Self::UnsupportedParams => {
                text::VAULT_UNREADABLE
            }
            Self::UnlockFailed => text::UNLOCK_FAILED,
            Self::PayloadCorrupt => text::PAYLOAD_CORRUPT,
            Self::UnsupportedPayload => text::PAYLOAD_NEWER,
            Self::SidecarCorrupt(_) | Self::SidecarVaultMismatch(_) => text::SIDECAR_UNREADABLE,
            Self::SidecarUnsupported(_) => text::SIDECAR_NEWER,
            Self::OutOfMemory => text::OUT_OF_MEMORY,
            Self::BackupNotConfirmed => text::BACKUP_NOT_CONFIRMED,
            Self::BackupMismatch => text::BACKUP_MISMATCH,
            Self::ChallengeStale => text::CHALLENGE_STALE,
            Self::RecordLimit => text::RECORD_LIMIT,
            Self::DuplicateKey => text::DUPLICATE_KEY,
            Self::NoMnemonic => text::NO_MNEMONIC,
            Self::LastKey => text::LAST_KEY,
            Self::PrimaryMnemonic => text::PRIMARY_MNEMONIC,
        };
        text.get(lang).to_owned()
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text_in(Lang::Ko))
    }
}

impl std::error::Error for VaultError {}

#[cfg(test)]
mod tests {
    use super::{KeyError, StorageError, VaultError, text};
    use crate::lang::{Lang, has_hangul, placeholders};
    use crate::vault::FileKind;

    #[test]
    fn english_error_texts_have_no_hangul_and_korean_is_unchanged() {
        let errors = [
            VaultError::Key(KeyError::MnemonicUnknownWord { position: 3 }),
            VaultError::Key(KeyError::WifFormat),
            VaultError::Key(KeyError::Internal),
            VaultError::Storage(StorageError::Io(5)),
            VaultError::UnlockFailed,
            VaultError::SidecarUnsupported(FileKind::Meta),
            VaultError::ChallengeStale,
            VaultError::NoMnemonic,
            VaultError::PrimaryMnemonic,
        ];
        for error in errors {
            let english = error.text_in(Lang::En);
            assert!(!english.is_empty() && !has_hangul(&english), "{error:?}");
            assert_eq!(error.to_string(), error.text_in(Lang::Ko));
        }
        assert_eq!(
            KeyError::MnemonicUnknownWord { position: 3 }.to_string(),
            "3번째 단어가 BIP39 영어 단어 목록에 없습니다."
        );
        assert_eq!(
            KeyError::MnemonicUnknownWord { position: 3 }.text_in(Lang::En),
            "Word 3 is not in the BIP39 English word list."
        );
        for entry in text::ALL {
            assert!(!has_hangul(entry.en), "{}", entry.name);
            let mut ko = placeholders(entry.ko);
            let mut en = placeholders(entry.en);
            ko.sort_unstable();
            en.sort_unstable();
            let expected: Vec<usize> = (0..entry.args).collect();
            assert!(ko == expected && en == expected, "{}", entry.name);
        }
    }
}
