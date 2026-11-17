//! The Windows `YubiKey` transports (spec/10 §4, §5.1): adapters from yw-win's PC/SC card and
//! CNG cipher to the yw-core `CardTransport` / `MgmtCipher` traits, and [`PcscSource`], the
//! [`CardSource`] of the real readers that the key worker gets from `main.rs`.
//!
//! (2026-11-17, spec/15 §11.4 S2: moved unchanged out of `yubikey`, which keeps the card
//! operations, the PIN types, `CardSource` and the emulator source; `yubikey` no longer calls
//! `yw_win`.)

use yw_core::secret::Zeroizing;
use yw_core::yubikey::piv::{MgmtAlgorithm, MgmtCipher};
use yw_core::yubikey::{CardError, CardTransport, TransportFault};
use yw_win::pcsc::{self, PcscFault};

use crate::yubikey::{CardSource, CardVisit};

const fn transport_error(fault: PcscFault) -> CardError {
    match fault {
        PcscFault::NoService => CardError::Transport(TransportFault::NoService),
        PcscFault::NoReader => CardError::Transport(TransportFault::NoReader),
        PcscFault::NoCard => CardError::Transport(TransportFault::NoCard),
        PcscFault::Busy => CardError::Transport(TransportFault::Busy),
        PcscFault::Removed => CardError::CardRemoved,
        PcscFault::Other => CardError::Transport(TransportFault::Io),
    }
}

/// A connected PC/SC card as a [`CardTransport`]. A job that sends anything but a read-only
/// instruction (`yubikey::needs_reset`: VERIFY, management-key authentication, signing, writes)
/// releases the card with a warm reset (spec/10 §5.1), so no PIN stays verified for the next
/// PC/SC client — between the PIN check and the signature, or after any card job.
#[derive(Debug)]
pub struct PcscTransport<'c> {
    card: pcsc::Card<'c>,
}

impl CardTransport for PcscTransport<'_> {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, CardError> {
        if yw_core::yubikey::needs_reset(command) {
            // Marked before the frame leaves: a command that fails half way still ends in a
            // reset.
            self.card.reset_on_release();
        }
        self.card
            .transmit(command)
            .map_err(|error| transport_error(pcsc::fault(&error)))
    }
}

/// Windows CNG as the PIV management-key cipher.
#[derive(Clone, Copy, Debug, Default)]
pub struct CngCipher;

impl CngCipher {
    fn run(
        algorithm: MgmtAlgorithm,
        key: &[u8],
        block: &[u8],
        encrypt: bool,
    ) -> Result<Zeroizing<Vec<u8>>, CardError> {
        let cipher = match algorithm {
            MgmtAlgorithm::TripleDes => yw_win::cng::BlockCipher::TripleDes,
            MgmtAlgorithm::Aes128 | MgmtAlgorithm::Aes192 | MgmtAlgorithm::Aes256 => {
                yw_win::cng::BlockCipher::Aes
            }
        };
        if key.len() != algorithm.key_len() {
            return Err(CardError::Internal);
        }
        yw_win::cng::ecb_block(cipher, key, block, encrypt)
            .map(Zeroizing::new)
            .map_err(|_| CardError::Internal)
    }
}

impl MgmtCipher for CngCipher {
    fn encrypt_block(
        &self,
        algorithm: MgmtAlgorithm,
        key: &[u8],
        block: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CardError> {
        Self::run(algorithm, key, block, true)
    }

    fn decrypt_block(
        &self,
        algorithm: MgmtAlgorithm,
        key: &[u8],
        block: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CardError> {
        Self::run(algorithm, key, block, false)
    }
}

/// The real readers (PC/SC, user scope).
#[derive(Debug, Default)]
pub struct PcscSource;

impl CardSource for PcscSource {
    fn each_card(&mut self, visit: &mut CardVisit<'_>) -> Result<(), CardError> {
        let context =
            pcsc::Context::establish().map_err(|error| transport_error(pcsc::fault(&error)))?;
        let readers = context
            .readers()
            .map_err(|error| transport_error(pcsc::fault(&error)))?;
        if readers.is_empty() {
            return Err(CardError::Transport(TransportFault::NoReader));
        }
        // A reader without a card is skipped silently; a card another program holds (gpg-agent,
        // scdaemon) or a reader error is remembered and reported when no card could be visited
        // (spec/10 §5.1: "다른 프로그램이 YubiKey를 쓰고 있습니다", not "찾을 수 없습니다").
        let mut fault: Option<PcscFault> = None;
        let mut visited = false;
        let mut note = |found: PcscFault| {
            if found != PcscFault::NoCard && fault != Some(PcscFault::Busy) {
                fault = Some(found);
            }
        };
        for reader in readers {
            let mut card = match context.connect(&reader) {
                Ok(card) => card,
                Err(error) => {
                    note(pcsc::fault(&error));
                    continue;
                }
            };
            if let Err(error) = card.begin_transaction() {
                note(pcsc::fault(&error));
                continue;
            }
            visited = true;
            let mut transport = PcscTransport { card };
            if visit(&mut transport, &CngCipher) {
                break;
            }
        }
        match fault {
            Some(found) if !visited => Err(transport_error(found)),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    /// `text` without its inline `#[cfg(test)] [pub(…)] mod name { … }` modules at column 0 (each
    /// ends at the first `}` line at column 0).
    fn without_test_modules(text: &str) -> String {
        let mut kept = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find("#[cfg(test)]\n") {
            let after = &rest[start + "#[cfg(test)]\n".len()..];
            let line = after.lines().next().unwrap_or("");
            let item = line
                .strip_prefix("pub(crate) ")
                .or_else(|| line.strip_prefix("pub(super) "))
                .unwrap_or(line);
            if item.starts_with("mod ") && item.ends_with(" {") {
                kept.push_str(&rest[..start]);
                rest = after
                    .find("\n}\n")
                    .map_or("", |end| &after[end + "\n}\n".len()..]);
            } else {
                kept.push_str(&rest[..start + "#[cfg(test)]\n".len()]);
                rest = after;
            }
        }
        kept.push_str(rest);
        kept
    }

    /// The source folders the scans read: yw-app's `src`, and yw-engine's once that crate
    /// exists (2026-11-17 S2 review: `yubikey.rs` and the key worker move there, and the scans
    /// must keep covering them; a folder that does not exist yet is skipped).
    fn source_roots() -> Vec<PathBuf> {
        let app = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut roots = vec![app.join("src")];
        let engine = app.join("..").join("yw-engine").join("src");
        if engine.is_dir() {
            roots.push(engine);
        }
        roots
    }

    /// Every `.rs` under `dir`, test code included.
    fn all_sources(dir: &Path, found: &mut Vec<(PathBuf, String)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                all_sources(&path, found);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                found.push((path, text));
            }
        }
    }

    /// The sources that are not test code: every `.rs` under `dir`, except files named
    /// `tests.rs` or under a `tests` folder, without their inline `#[cfg(test)]` modules.
    fn production_sources(dir: &Path, found: &mut Vec<(PathBuf, String)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.is_dir() {
                if name != "tests" {
                    production_sources(&path, found);
                }
            } else if path.extension().is_some_and(|extension| extension == "rs")
                && name != "tests.rs"
            {
                let text = std::fs::read_to_string(&path).unwrap();
                found.push((path, without_test_modules(&text)));
            }
        }
    }

    /// The emulator source is always compiled (`yubikey::MockSource`, spec/15 §11.4 S2) but only
    /// test code may build one: production code never constructs or names it outside its own
    /// definition, so the key worker can only get the PC/SC readers.
    #[test]
    fn mock_source_is_built_only_by_tests() {
        let mut sources = Vec::new();
        for root in source_roots() {
            production_sources(&root, &mut sources);
        }
        assert!(sources.len() > 100, "{}", sources.len());
        let mut offenders = Vec::new();
        for (path, text) in &sources {
            let allowed: &[&str] = if path.ends_with("yubikey.rs") {
                &[
                    "pub struct MockSource {",
                    "impl CardSource for MockSource {",
                    "impl std::fmt::Debug for MockSource {",
                    "debug_struct(\"MockSource\")",
                ]
            } else {
                &[]
            };
            let mut rest = text.clone();
            for definition in allowed {
                rest = rest.replace(definition, "");
            }
            if rest.contains("MockSource") {
                offenders.push(path.display().to_string());
            }
        }
        assert!(offenders.is_empty(), "{offenders:?}");
    }

    /// Only `main.rs` gives the key worker the machine's PC/SC readers (2026-11-17 S2 review,
    /// AGENTS rule 3): in every source, test code included (`src` and `tests` of yw-app and,
    /// once it exists, yw-engine), `WinKeyPlatform::deps()` is called only by `main.rs` and
    /// `PcscSource` is named in code only by its definition and `store.rs` (`deps`). Tests on
    /// real files use `WinKeyPlatform::deps_with_cards` with `yubikey::NoReaders` or the
    /// emulator. Comment lines are not code.
    #[test]
    fn pcsc_readers_only_from_main() {
        let mut sources = Vec::new();
        for root in source_roots() {
            all_sources(&root, &mut sources);
            let tests = root.join("..").join("tests");
            if tests.is_dir() {
                all_sources(&tests, &mut sources);
            }
        }
        assert!(sources.len() > 150, "{}", sources.len());
        let mut offenders = Vec::new();
        for (path, text) in &sources {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let code: String = text
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            let pcsc_allowed = name == "card_pcsc.rs" || name == "store.rs";
            let deps_allowed = name == "main.rs" || name == "card_pcsc.rs";
            if (code.contains("PcscSource") && !pcsc_allowed)
                || (code.contains("WinKeyPlatform::deps()") && !deps_allowed)
            {
                offenders.push(path.display().to_string());
            }
        }
        assert!(offenders.is_empty(), "{offenders:?}");
    }
}
