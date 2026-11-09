//! Journal I/O on the key worker (spec/02 §5.4, spec/03 §5): the worker owns the decrypted
//! journal plaintext while unlocked, signs approved transactions and commits their `Signed`
//! record before anything is sent (§5.3), applies state transitions, and moves terminal groups to
//! meta `activity` (meta first, then the journal, so a crash in between repeats an idempotent
//! move).

use yw_core::approval::{AccountRef, Approved, ChainRef};
use yw_core::error::{StorageError, VaultError};
use yw_core::evm::sign::{SignError, SignedTx, sign_transaction};
use yw_core::journal::JournalPlain;
use yw_core::journal::evm::{
    ActivityRow, EvmEntries, EvmRecord, Transition, apply_to_plain, make_room, push_record,
    room_after_cleanup, take_expired,
};
use yw_core::journal::sol::{
    SolActivityRow, SolEntries, SolRecord, SolTransition, has_intent, has_room as sol_has_room,
    make_room as sol_make_room, pending_for, push_record as sol_push_record, take_terminal,
};
use yw_core::sol::{SignedSolTransfer, SolSignError, sign_transfer};

/// The signing step of a SOL transfer: `(vault, approval, consumed_at_ms, blockhash, now_ms)`
/// → the signed and verified transfer (the vault's `sign_transfer` or the card path).
pub type SolSigner<'a> = dyn FnMut(&Vault, Approved, u64, [u8; 32], u64) -> Result<SignedSolTransfer, SolSignFailure>
    + 'a;
use yw_core::vault::{FileKind, Vault};

use crate::events::{
    JournalView, KeyOutcome, SignFailure, SignInfo, SignedSummary, SolSignFailure, SolSignedSummary,
};
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

/// Times and blockhash of one SOL signing (spec/07 §13.1 steps 5–6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SolSignTimes {
    /// Monotonic ms of `consume`.
    pub consumed_at_ms: u64,
    /// Finalized blockhash.
    pub blockhash: [u8; 32],
    /// Its `lastValidBlockHeight`.
    pub last_valid_block_height: u64,
    /// Wall clock (journal `signed_at_ms`).
    pub now_unix_ms: u64,
}

#[path = "journal_btc.rs"]
pub mod btc;

#[path = "journal_zec.rs"]
pub mod zec;

/// The journal state the key worker keeps between jobs, with the authoritative `BtcMeta` of
/// the unlocked session (spec/08 §12.3: the key worker is the only writer of meta `btc`; every
/// meta document the UI saves gets this copy).
#[derive(Debug, Default)]
pub struct JournalState {
    plain: Option<JournalPlain>,
    overlay: Vec<(NetworkId, ActivityEntry)>,
    btc: Option<yw_core::btc::BtcMeta>,
    btc_accounts: yw_core::btc::BtcAccounts,
    btc_loaded: bool,
}

/// The view sent to the UI.
#[must_use]
pub fn view_of(plain: &JournalPlain) -> JournalView {
    let entries = EvmEntries::from_plain(plain);
    let sol = SolEntries::from_plain(plain);
    let btc = yw_core::journal::btc::BtcEntries::from_plain(plain);
    let zec = yw_core::journal::zec::ZecEntries::from_plain(plain);
    let mut trial = plain.clone();
    JournalView {
        records: entries.records(),
        corrupt: entries.corrupt,
        room: room_after_cleanup(plain),
        sol_records: sol.records(),
        sol_corrupt: sol.corrupt,
        sol_room: sol_make_room(&mut trial, 0).is_ok(),
        btc_records: btc.records(),
        btc_corrupt: btc.corrupt,
        btc_room: yw_core::journal::btc::has_room(plain),
        zec_records: zec.records(),
        zec_corrupt: zec.corrupt,
    }
}

/// `solana:<cluster>` of a core cluster.
#[must_use]
pub const fn sol_network(cluster: yw_core::sol::SolCluster) -> NetworkId {
    NetworkId::Solana(match cluster {
        yw_core::sol::SolCluster::Mainnet => crate::network::SolCluster::Mainnet,
        yw_core::sol::SolCluster::Devnet => crate::network::SolCluster::Devnet,
    })
}

/// After a journal write that reported a failure: the journal read back from disk when it holds
/// `record` exactly (the write landed anyway), `None` when it does not or cannot be read.
fn written_anyway(vault: &Vault, record: &SolRecord) -> Option<JournalPlain> {
    let (_, bytes) = vault.open_sidecar(FileKind::Journal).ok().flatten()?;
    let plain = JournalPlain::decode(bytes.expose()).ok()?;
    SolEntries::from_plain(&plain)
        .records()
        .contains(record)
        .then_some(plain)
}

/// A SOL activity row as a meta `ActivityEntry` of `solana:<cluster>` (spec/07 §14.1 table).
#[must_use]
pub fn sol_activity(row: &SolActivityRow) -> (NetworkId, ActivityEntry) {
    (
        sol_network(row.cluster),
        ActivityEntry {
            account: row.account.clone(),
            tx_id: row.tx_id.clone(),
            title: row.title.clone(),
            asset: row.asset.clone(),
            amount: row.amount.clone(),
            counterparty: row.counterparty.clone(),
            status: row.status.to_owned(),
            time_unix_ms: row.time_unix_ms,
        },
    )
}

impl JournalState {
    /// Forgets everything (lock).
    pub fn clear(&mut self) {
        self.plain = None;
        self.overlay.clear();
        self.btc = None;
        self.btc_accounts = yw_core::btc::BtcAccounts::default();
        self.btc_loaded = false;
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
            Some((_, bytes)) => JournalPlain::decode(bytes.expose())?,
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
                meta::parse(plaintext.expose())
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
        self.apply_btc_meta(vault, &mut document);
        vault.save_sidecar(FileKind::Meta, &document.to_json())?;
        self.overlay.extend(moved.iter().cloned());
        Ok(moved)
    }

    /// Writes SOL terminal rows into meta `activity` (skipped in alt-passphrase sessions).
    fn persist_sol_activity(
        &mut self,
        vault: &mut Vault,
        rows: &[SolActivityRow],
        alt: bool,
    ) -> Result<Vec<(NetworkId, ActivityEntry)>, VaultError> {
        if rows.is_empty() || alt {
            return Ok(Vec::new());
        }
        let mut document = match vault.open_sidecar(FileKind::Meta)? {
            None => Meta::default(),
            Some((_, plaintext)) => {
                meta::parse(plaintext.expose())
                    .map_err(|_| VaultError::SidecarCorrupt(FileKind::Meta))?
                    .meta
            }
        };
        let moved: Vec<(NetworkId, ActivityEntry)> = rows.iter().map(sol_activity).collect();
        for (network, entry) in &moved {
            document.upsert_activity(&network.to_string(), entry);
        }
        self.apply_btc_meta(vault, &mut document);
        vault.save_sidecar(FileKind::Meta, &document.to_json())?;
        self.overlay.extend(moved.iter().cloned());
        Ok(moved)
    }

    /// Signs an approved SOL transfer (spec/07 §13.1 steps 6–7): room check (terminal SOL
    /// records move to activity first), `AlreadySigned` check, `sign_transfer` with its
    /// post-sign verification, the `Pending` record committed — only then is the transaction
    /// returned for broadcast. A failed journal write drops the signature (never sent).
    pub fn sign_sol(
        &mut self,
        vault: &mut Vault,
        approved: Box<Approved>,
        times: SolSignTimes,
        alt: bool,
    ) -> Vec<KeyOutcome> {
        self.sign_sol_with(
            vault,
            approved,
            times,
            alt,
            &mut |vault, approved, consumed_at_ms, blockhash, now_ms| {
                sign_transfer(vault, approved, consumed_at_ms, blockhash, now_ms)
                    .map_err(SolSignFailure::Sign)
            },
        )
    }

    /// [`JournalState::sign_sol`] with another signer: the `YubiKey` path (spec/10 §6.4) passes
    /// the card signer (`sol::sign::sign_transfer_card`); the `AlreadySigned`/`PendingExists`
    /// and room checks before signing and the `Pending` commit before anything is returned are
    /// the same.
    pub fn sign_sol_with(
        &mut self,
        vault: &mut Vault,
        approved: Box<Approved>,
        times: SolSignTimes,
        alt: bool,
        sign_step: &mut SolSigner<'_>,
    ) -> Vec<KeyOutcome> {
        let mut out = Vec::new();
        let result = self.sign_sol_inner(vault, *approved, times, alt, &mut out, sign_step);
        out.insert(0, KeyOutcome::SignedSol(result));
        out
    }

    fn sign_sol_inner(
        &mut self,
        vault: &mut Vault,
        approved: Approved,
        times: SolSignTimes,
        alt: bool,
        out: &mut Vec<KeyOutcome>,
        sign_step: &mut SolSigner<'_>,
    ) -> Result<SolSignedSummary, SolSignFailure> {
        let yw_core::approval::SigningPayload::SolTransfer(intent) = approved.payload() else {
            return Err(SolSignFailure::Sign(SolSignError::KindMismatch));
        };
        let intent = *intent;
        let current = self.current(vault).map_err(SolSignFailure::JournalWrite)?;
        let mut trial = current;
        if has_intent(&trial, &intent.intent_hash()) {
            return Err(SolSignFailure::AlreadySigned);
        }
        // One `Pending` per (cluster, account) (spec/07 §1), checked again on the journal itself.
        if pending_for(
            &SolEntries::from_plain(&trial).records(),
            intent.cluster,
            &intent.core.from,
        )
        .is_some()
        {
            return Err(SolSignFailure::Sign(SolSignError::PendingExists));
        }
        if !sol_has_room(&trial) {
            let rows = sol_make_room(&mut trial, times.now_unix_ms)
                .map_err(|_| SolSignFailure::JournalFull)?;
            match self.persist_sol_activity(vault, &rows, alt) {
                Ok(moved) if !moved.is_empty() => out.push(KeyOutcome::ActivityMoved(moved)),
                Ok(_) => {}
                Err(_) => return Err(SolSignFailure::JournalFull),
            }
        }
        let now_ms = yw_win::time::monotonic_ms();
        let signed = sign_step(
            vault,
            approved,
            times.consumed_at_ms,
            times.blockhash,
            now_ms,
        )?;
        let record = SolRecord::new_pending(
            &intent,
            &signed,
            times.now_unix_ms,
            times.last_valid_block_height,
        );
        sol_push_record(&mut trial, &record).map_err(|_| SolSignFailure::JournalFull)?;
        let bytes = trial.encode().map_err(|_| SolSignFailure::JournalFull)?;
        if let Err(error) = vault.save_sidecar(FileKind::Journal, &bytes) {
            // A write can reach the disk and still report a failure (e.g. after the rename). A
            // `Pending` record on disk will be resumed and broadcast after a restart, so it must
            // never be reported as "not written": read the journal back, and if this record is
            // there, track it like a written one (spec/07 §13.1-7).
            let Some(on_disk) = written_anyway(vault, &record) else {
                logging::warn("journal", "journal.sol_pending_write_failed", &[]);
                return Err(SolSignFailure::JournalWrite(error));
            };
            logging::warn("journal", "journal.sol_pending_write_found_on_disk", &[]);
            trial = on_disk;
        }
        logging::info(
            "journal",
            "journal.sol_pending",
            &[("net", Field::Net(sol_network(intent.cluster)))],
        );
        out.push(KeyOutcome::Journal(Ok(view_of(&trial))));
        self.plain = Some(trial);
        fault_point("sol.after_journal_pending");
        Ok(SolSignedSummary {
            cluster: intent.cluster,
            from: intent.core.from,
            signature: signed.signature,
            tx: signed.tx,
            signed_at_ms: times.now_unix_ms,
            last_valid_block_height: times.last_valid_block_height,
        })
    }

    /// Applies a SOL transition, moves terminal records to activity (meta first) and commits.
    pub fn apply_sol(
        &mut self,
        vault: &mut Vault,
        transition: &SolTransition,
        now_unix_ms: u64,
        alt: bool,
    ) -> Vec<KeyOutcome> {
        let mut next = match self.current(vault) {
            Ok(plain) => plain,
            Err(error) => return vec![KeyOutcome::Journal(Err(error))],
        };
        let changed = yw_core::journal::sol::apply(&mut next, transition);
        logging::info(
            "journal",
            "journal.sol_transition",
            &[
                ("kind", Field::Word(transition.name())),
                ("changed", Field::Word(if changed { "yes" } else { "no" })),
            ],
        );
        let mut pruned = next.clone();
        let rows = take_terminal(&mut pruned, now_unix_ms);
        let mut moved = Vec::new();
        if !rows.is_empty()
            && let Ok(rows_moved) = self.persist_sol_activity(vault, &rows, alt)
            && !rows_moved.is_empty()
        {
            moved = rows_moved;
            next = pruned;
        }
        if !changed && moved.is_empty() {
            return vec![KeyOutcome::Journal(Ok(view_of(&next)))];
        }
        let Ok(bytes) = next.encode() else {
            return vec![KeyOutcome::Journal(Err(VaultError::Storage(
                StorageError::TooLarge,
            )))];
        };
        match vault.save_sidecar(FileKind::Journal, &bytes) {
            Ok(_) => {
                let view = view_of(&next);
                self.plain = Some(next);
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

    /// Whether a journal record of an account of the added mnemonic `id` may still confirm: a
    /// SOL `Pending`, a ZEC record not final, a BTC record in flight / replaced / given up or
    /// refused inside the 30-day window (spec/02 §8.6). The records cannot be checked — an
    /// unreadable journal, or a damaged SOL, BTC or ZEC record (whose account is unknown) —
    /// counts as busy (the rule of [`Self::zec_imported_busy`]).
    pub fn mnemonic_busy(
        &mut self,
        vault: &Vault,
        id: yw_core::vault::RecordId,
        now_unix: u64,
    ) -> bool {
        let Ok(plain) = self.current(vault) else {
            return true;
        };
        let sol = yw_core::journal::sol::SolEntries::from_plain(&plain);
        let zec = yw_core::journal::zec::ZecEntries::from_plain(&plain);
        let btc_corrupt = yw_core::journal::btc::BtcEntries::from_plain(&plain).corrupt;
        if sol.corrupt > 0 || zec.corrupt > 0 || btc_corrupt > 0 {
            logging::warn("journal", "journal.mnemonic_busy_damaged", &[]);
            return true;
        }
        let sol = sol.records.iter().any(|(_, record)| {
            record.state == yw_core::journal::sol::SolTxState::Pending
                && record.source.mnemonic() == Some(id)
        });
        let zec = zec.records.iter().any(|(_, record)| {
            record.account.source.mnemonic() == Some(id) && record.may_still_confirm()
        });
        sol || zec || self.btc_mnemonic_busy(vault, id, now_unix)
    }

    /// Whether the imported Zcash key `id` (vault tag 6) must stay: a ZEC record of its account
    /// may still confirm, or the records cannot be checked — an unreadable journal or a damaged
    /// ZEC record counts as busy (the rule of [`Self::mnemonic_busy`]). `false` for a key that
    /// is not a Zcash key.
    pub fn zec_imported_busy(&mut self, vault: &Vault, id: yw_core::vault::RecordId) -> bool {
        let info = match vault.imported_keys() {
            Ok(keys) => match keys.zec.into_iter().find(|(record, _)| *record == id) {
                Some((_, info)) => info,
                None => return false,
            },
            // The key list cannot be read: whether it is a Zcash key is unknown.
            Err(_) => return true,
        };
        let Ok(plain) = self.current(vault) else {
            return true;
        };
        let zec = yw_core::journal::zec::ZecEntries::from_plain(&plain);
        zec.corrupt > 0
            || zec.records.iter().any(|(_, record)| {
                record.account.network == info.network
                    && record.account.pubkey == info.pubkey
                    && record.may_still_confirm()
            })
    }

    /// Whether a journal record of an account in `lost` — the uses of `YubiKey` keys no card
    /// would hold after a card record is removed, cleared or re-slotted (spec/10 §15) — may
    /// still confirm: an EVM record not final (its nonce group is open), a SOL `Pending`, a BTC
    /// record of that card account (`BtcRecord::may_still_confirm`), a ZEC record not final.
    /// The records cannot be checked — an unreadable journal or a damaged record of any chain,
    /// whose account is unknown — counts as busy (the rule of [`Self::mnemonic_busy`]).
    pub fn hardware_busy(
        &mut self,
        vault: &Vault,
        lost: &[crate::workers::key::yubikey::CardUse],
        now_unix: u64,
    ) -> bool {
        use crate::workers::key::yubikey::CardUse;
        let Ok(plain) = self.current(vault) else {
            return true;
        };
        let evm = EvmEntries::from_plain(&plain);
        let sol = SolEntries::from_plain(&plain);
        let btc = yw_core::journal::btc::BtcEntries::from_plain(&plain);
        let zec = yw_core::journal::zec::ZecEntries::from_plain(&plain);
        if evm.corrupt > 0 || sol.corrupt > 0 || btc.corrupt > 0 || zec.corrupt > 0 {
            logging::warn("journal", "journal.hardware_busy_damaged", &[]);
            return true;
        }
        let btc = btc.records();
        lost.iter().any(|card_use| match *card_use {
            CardUse::Evm(address) => evm
                .records
                .iter()
                .any(|(_, record)| record.account == address && !record.state.is_terminal()),
            CardUse::Btc(network, key, script_type) => {
                let account = yw_core::btc::BtcAccountId::Hardware { key, script_type };
                btc.iter().any(|record| {
                    record.network == network
                        && record.account == account
                        && record.may_still_confirm(now_unix)
                })
            }
            CardUse::Sol(index) => sol.records.iter().any(|(_, record)| {
                record.state == yw_core::journal::sol::SolTxState::Pending
                    && record.source == yw_core::slip10::SolKeySource::Hardware(index)
            }),
            CardUse::Zec(network, index) => zec.records.iter().any(|(_, record)| {
                record.account.network == network
                    && record.account.source == yw_core::zec::ZecKeySource::Hardware { index }
                    && record.may_still_confirm()
            }),
        })
    }

    /// Drops the (final) SOL, BTC and ZEC records of the removed mnemonic `id`'s accounts and
    /// commits: their accounts are gone, and an earlier build would read these record versions
    /// as damaged bodies (spec/04 §6.6). Nothing is written when there is none.
    pub fn purge_mnemonic(
        &mut self,
        vault: &mut Vault,
        id: yw_core::vault::RecordId,
        alt: bool,
    ) -> Vec<KeyOutcome> {
        let Ok(mut next) = self.current(vault) else {
            return Vec::new();
        };
        let before = next.entries.len();
        next.entries.retain(|entry| match entry.kind {
            yw_core::journal::EntryKind::Sol => {
                yw_core::journal::sol::SolRecord::decode(&entry.body)
                    .map_or(true, |record| record.source.mnemonic() != Some(id))
            }
            yw_core::journal::EntryKind::Btc => {
                yw_core::journal::btc::BtcRecord::decode(&entry.body).map_or(true, |record| {
                    !matches!(
                        record.account,
                        yw_core::btc::BtcAccountId::Hd { mnemonic: Some(of), .. } if of == id
                    )
                })
            }
            yw_core::journal::EntryKind::Zec => {
                yw_core::journal::zec::ZecRecord::decode(&entry.body)
                    .map_or(true, |record| record.account.source.mnemonic() != Some(id))
            }
            yw_core::journal::EntryKind::Evm => true,
        });
        if next.entries.len() == before {
            return Vec::new();
        }
        let _ = alt;
        let Ok(bytes) = next.encode() else {
            return Vec::new();
        };
        match vault.save_sidecar(FileKind::Journal, &bytes) {
            Ok(_) => {
                let view = view_of(&next);
                self.plain = Some(next);
                vec![KeyOutcome::Journal(Ok(view))]
            }
            Err(error) => {
                logging::warn("journal", "journal.write_failed", &[]);
                vec![KeyOutcome::Journal(Err(error))]
            }
        }
    }

    /// Re-applies this session's moved activity rows and the key worker's `BtcMeta` to a meta
    /// document from the UI (imported-key accounts without a vault record are left out).
    pub fn merge_overlay(&self, vault: &Vault, document: &mut Meta) {
        for (network, entry) in &self.overlay {
            document.upsert_activity(&network.to_string(), entry);
        }
        self.apply_btc_meta(vault, document);
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
    /// only then is the result returned for broadcast (spec/03 §5.3). The result carries the
    /// job's `ticket` (its waiter on the UI thread).
    pub fn sign(
        &mut self,
        vault: &mut Vault,
        ticket: crate::events::SignTicket,
        approved: Box<Approved>,
        info: &SignInfo,
        alt: bool,
    ) -> Vec<KeyOutcome> {
        self.sign_with(
            vault,
            ticket,
            approved,
            info,
            alt,
            &mut |vault, approved| sign_transaction(vault, approved).map_err(SignFailure::Sign),
        )
    }

    /// [`JournalState::sign`] with another signer: the `YubiKey` path (spec/10 §9.2) passes the
    /// card signer; room check, post-sign verification (inside the signer) and the `Signed`
    /// commit before anything is returned are the same.
    pub fn sign_with(
        &mut self,
        vault: &mut Vault,
        ticket: crate::events::SignTicket,
        approved: Box<Approved>,
        info: &SignInfo,
        alt: bool,
        sign_fn: &mut dyn FnMut(&Vault, Approved) -> Result<SignedTx, SignFailure>,
    ) -> Vec<KeyOutcome> {
        let mut out = Vec::new();
        let result = self.sign_inner(vault, *approved, info, alt, &mut out, sign_fn);
        out.insert(
            0,
            KeyOutcome::SignedEvm(crate::events::EvmSigned { ticket, result }),
        );
        out
    }

    fn sign_inner(
        &mut self,
        vault: &mut Vault,
        approved: Approved,
        info: &SignInfo,
        alt: bool,
        out: &mut Vec<KeyOutcome>,
        sign_fn: &mut dyn FnMut(&Vault, Approved) -> Result<SignedTx, SignFailure>,
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
        let (ChainRef::Evm { chain_id, .. }, AccountRef::Evm(account)) =
            (approved.chain(), approved.account())
        else {
            return Err(SignFailure::Sign(SignError::KindMismatch));
        };
        let digest = approved.digest();
        let signed = sign_fn(vault, approved)?;
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
