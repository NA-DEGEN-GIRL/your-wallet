//! Journal I/O on the key worker (spec/02 §5.4, spec/03 §5): the worker owns the decrypted
//! journal plaintext while unlocked, signs approved transactions and commits their `Signed`
//! record before anything is sent (§5.3), applies state transitions, and moves terminal groups to
//! meta `activity` (meta first, then the journal, so a crash in between repeats an idempotent
//! move).

use yw_core::approval::{AccountRef, Approved, ChainRef};
use yw_core::error::{StorageError, VaultError};
use yw_core::evm::sign::{SignError, sign_transaction};
use yw_core::journal::JournalPlain;
use yw_core::journal::evm::{
    ActivityRow, EvmEntries, EvmRecord, Transition, apply_to_plain, make_room, push_record,
    room_after_cleanup, take_expired,
};
use yw_core::vault::{FileKind, Vault};

use crate::events::{JournalView, KeyOutcome, SignFailure, SignInfo, SignedSummary};
use crate::logging::{self, Field};
use crate::meta::{self, ActivityEntry, Meta};
use crate::network::NetworkId;

/// Debug builds only: aborts when `YW_FAULT_POINT` names this point (spec/09 §2.1, M4-8).
pub fn fault_point(name: &str) {
    if cfg!(debug_assertions)
        && std::env::var_os("YW_FAULT_POINT").is_some_and(|value| value == name)
    {
        logging::warn("app", "fault_point", &[]);
        logging::flush();
        std::process::abort();
    }
}

/// The journal state the key worker keeps between jobs.
#[derive(Debug, Default)]
pub struct JournalState {
    plain: Option<JournalPlain>,
    overlay: Vec<(NetworkId, ActivityEntry)>,
}

/// The view sent to the UI.
#[must_use]
pub fn view_of(plain: &JournalPlain) -> JournalView {
    let entries = EvmEntries::from_plain(plain);
    JournalView {
        records: entries.records(),
        corrupt: entries.corrupt,
        room: room_after_cleanup(plain),
    }
}

impl JournalState {
    /// Forgets everything (lock).
    pub fn clear(&mut self) {
        self.plain = None;
        self.overlay.clear();
    }

    /// Activity rows moved this session (re-applied to every meta save from the UI).
    #[must_use]
    pub fn overlay(&self) -> &[(NetworkId, ActivityEntry)] {
        &self.overlay
    }

    /// Reads and decodes the journal.
    ///
    /// # Errors
    ///
    /// Vault errors; `SidecarCorrupt(Journal)` for framing errors (E-VLT-006 choice).
    pub fn load(&mut self, vault: &Vault) -> Result<JournalView, VaultError> {
        let plain = match vault.open_sidecar(FileKind::Journal)? {
            None => JournalPlain::default(),
            Some((_, bytes)) => JournalPlain::decode(&bytes)?,
        };
        let view = view_of(&plain);
        self.plain = Some(plain);
        Ok(view)
    }

    fn current(&mut self, vault: &Vault) -> Result<JournalPlain, VaultError> {
        if self.plain.is_none() {
            self.load(vault)?;
        }
        self.plain
            .clone()
            .ok_or(VaultError::SidecarCorrupt(FileKind::Journal))
    }

    /// Writes `rows` into meta `activity` (skipped in alt-passphrase sessions, whose meta is
    /// never stored).
    fn persist_activity(
        &mut self,
        vault: &mut Vault,
        rows: &[ActivityRow],
        alt: bool,
    ) -> Result<Vec<(NetworkId, ActivityEntry)>, VaultError> {
        if rows.is_empty() || alt {
            return Ok(Vec::new());
        }
        let mut document = match vault.open_sidecar(FileKind::Meta)? {
            None => Meta::default(),
            Some((_, plaintext)) => {
                meta::parse(&plaintext)
                    .map_err(|_| VaultError::SidecarCorrupt(FileKind::Meta))?
                    .meta
            }
        };
        let moved: Vec<(NetworkId, ActivityEntry)> = rows
            .iter()
            .map(|row| {
                (
                    NetworkId::Eip155(row.chain_id),
                    ActivityEntry::from_row(row),
                )
            })
            .collect();
        for (network, entry) in &moved {
            document.upsert_activity(&network.to_string(), entry);
        }
        vault.save_sidecar(FileKind::Meta, &document.to_json())?;
        self.overlay.extend(moved.iter().cloned());
        Ok(moved)
    }

    /// Re-applies this session's moved activity rows to a meta document from the UI.
    pub fn merge_overlay(&self, document: &mut Meta) {
        for (network, entry) in &self.overlay {
            document.upsert_activity(&network.to_string(), entry);
        }
    }

    /// Prunes 7-day-old terminal groups into activity (when that write succeeds), then commits.
    fn commit(
        &mut self,
        vault: &mut Vault,
        next: JournalPlain,
        now_unix_ms: u64,
        alt: bool,
    ) -> Result<(JournalView, Vec<(NetworkId, ActivityEntry)>), VaultError> {
        let mut pruned = next.clone();
        let rows = take_expired(&mut pruned, now_unix_ms);
        let (next, moved) = if rows.is_empty() || alt {
            (next, Vec::new())
        } else {
            match self.persist_activity(vault, &rows, alt) {
                Ok(moved) => (pruned, moved),
                Err(_) => (next, Vec::new()),
            }
        };
        let bytes = next
            .encode()
            .map_err(|_| VaultError::Storage(StorageError::TooLarge))?;
        vault.save_sidecar(FileKind::Journal, &bytes)?;
        let view = view_of(&next);
        self.plain = Some(next);
        Ok((view, moved))
    }

    /// Applies transitions and commits.
    pub fn apply(
        &mut self,
        vault: &mut Vault,
        transitions: &[Transition],
        now_unix_ms: u64,
        alt: bool,
    ) -> Vec<KeyOutcome> {
        let mut next = match self.current(vault) {
            Ok(plain) => plain,
            Err(error) => return vec![KeyOutcome::Journal(Err(error))],
        };
        let changed = apply_to_plain(&mut next, transitions);
        for transition in transitions {
            logging::info(
                "journal",
                "journal.transition",
                &[("kind", Field::Word(transition.name()))],
            );
        }
        if changed == 0 {
            return vec![KeyOutcome::Journal(Ok(view_of(&next)))];
        }
        match self.commit(vault, next, now_unix_ms, alt) {
            Ok((view, moved)) => {
                let mut out = vec![KeyOutcome::Journal(Ok(view))];
                if !moved.is_empty() {
                    out.push(KeyOutcome::ActivityMoved(moved));
                }
                out
            }
            Err(error) => {
                logging::warn("journal", "journal.write_failed", &[]);
                vec![KeyOutcome::Journal(Err(error))]
            }
        }
    }

    /// Signs an approved transaction: room check (moving terminal groups to activity if
    /// needed), `sign_transaction` with post-sign verification, the `Signed` record committed —
    /// only then is the result returned for broadcast (spec/03 §5.3).
    pub fn sign(
        &mut self,
        vault: &mut Vault,
        approved: Box<Approved>,
        info: &SignInfo,
        alt: bool,
    ) -> Vec<KeyOutcome> {
        let mut out = Vec::new();
        let result = self.sign_inner(vault, *approved, info, alt, &mut out);
        out.insert(0, KeyOutcome::SignedEvm(result));
        out
    }

    fn sign_inner(
        &mut self,
        vault: &mut Vault,
        approved: Approved,
        info: &SignInfo,
        alt: bool,
        out: &mut Vec<KeyOutcome>,
    ) -> Result<SignedSummary, SignFailure> {
        let current = self.current(vault).map_err(SignFailure::JournalWrite)?;
        let mut trial = current.clone();
        // §5.4-4: groups terminal for 7 days move on every journal write, this one included.
        let mut rows = if alt {
            Vec::new()
        } else {
            take_expired(&mut trial, info.now_unix_ms)
        };
        let retention_only = rows.len();
        rows.extend(make_room(&mut trial).map_err(|_| SignFailure::JournalFull)?);
        if !rows.is_empty() {
            match self.persist_activity(vault, &rows, alt) {
                Ok(moved) if !moved.is_empty() => out.push(KeyOutcome::ActivityMoved(moved)),
                Ok(_) => {}
                // Only the retention move failed: keep those groups for a later write.
                Err(_) if rows.len() == retention_only => trial = current,
                Err(_) => return Err(SignFailure::JournalFull),
            }
        }
        let ChainRef::Evm { chain_id, .. } = approved.chain();
        let AccountRef::Evm(account) = approved.account();
        let digest = approved.digest();
        let signed = sign_transaction(vault, approved).map_err(SignFailure::Sign)?;
        let record = EvmRecord::new_signed(
            chain_id,
            account,
            signed.tx.nonce,
            info.role,
            info.now_unix_ms,
            digest,
            &info.origin,
            &info.label,
            signed.raw.clone(),
        )
        .map_err(|_| SignFailure::Sign(SignError::PostSignVerification))?;
        push_record(&mut trial, &record).map_err(|_| SignFailure::JournalFull)?;
        let bytes = trial.encode().map_err(|_| SignFailure::JournalFull)?;
        if let Err(error) = vault.save_sidecar(FileKind::Journal, &bytes) {
            logging::warn("journal", "journal.signed_write_failed", &[]);
            return Err(SignFailure::JournalWrite(error));
        }
        logging::info(
            "journal",
            "journal.signed",
            &[
                ("net", Field::Net(NetworkId::Eip155(chain_id))),
                ("account", Field::Address(account.as_bytes())),
                ("nonce", Field::Num(signed.tx.nonce)),
                ("tx", Field::Hash(&signed.tx_hash)),
            ],
        );
        out.push(KeyOutcome::Journal(Ok(view_of(&trial))));
        self.plain = Some(trial);
        fault_point("evm.after_journal_signed");
        Ok(SignedSummary {
            chain_id,
            account,
            nonce: signed.tx.nonce,
            raw: signed.raw,
            tx_hash: signed.tx_hash,
        })
    }
}
