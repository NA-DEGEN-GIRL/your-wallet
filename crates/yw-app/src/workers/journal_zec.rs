//! Zcash journal steps on the key worker (spec/12 §10–§12): the account public key, signing an
//! approved plan (vault key or `YubiKey`) with its `Signed` record committed before anything is
//! returned for broadcast, and state transitions (disclose, broadcast, reject, mined, expired).

use yw_core::approval::Approved;
use yw_core::journal::zec::{
    ZecJournalBlock, ZecRecord, ZecTransition, ZecTxState, apply, check_plan_allowed, push_record,
};
use yw_core::lang::Lang;
use yw_core::vault::{FileKind, Vault};
use yw_core::zec::{ZecAccount, ZecKeySource, ZecNetwork, ZecPlan, ZecSignError, ZecSignedTx};

use super::{JournalState, view_of};
use crate::events::KeyOutcome;
use crate::logging::{self, Field};
use crate::network::NetworkId;

/// A Zcash key-worker job.
pub enum ZecKeyJob {
    /// The compressed public key of a vault key source (derived path or EVM key).
    PublicKey {
        /// Network.
        network: ZecNetwork,
        /// Source.
        source: ZecKeySource,
    },
    /// Sign an approved plan with the vault, verify it and commit its `Signed` record.
    Sign {
        /// The one-time approval (moved).
        approved: Box<Approved>,
        /// The approved plan.
        plan: Box<ZecPlan>,
        /// Wall clock.
        now_unix_ms: u64,
    },
    /// [`ZecKeyJob::Sign`] on a `YubiKey` (spec/10 §6.4): one card signature per input.
    SignCard {
        /// The one-time approval (moved).
        approved: Box<Approved>,
        /// The approved plan.
        plan: Box<ZecPlan>,
        /// Wall clock.
        now_unix_ms: u64,
        /// The card PIN for this one operation.
        pin: yw_core::secret::Zeroizing<Vec<u8>>,
    },
    /// Apply a journal transition to the record `txid` (internal order).
    Journal {
        /// Txid.
        txid: [u8; 32],
        /// Transition.
        transition: ZecTransition,
    },
}

impl core::fmt::Debug for ZecKeyJob {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.name())
    }
}

impl ZecKeyJob {
    /// Fixed name for logs.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::PublicKey { .. } => "ZecPublicKey",
            Self::Sign { .. } => "SignZec",
            Self::SignCard { .. } => "SignZecCard",
            Self::Journal { .. } => "ZecJournal",
        }
    }
}

/// A signed, verified and journaled transaction for the UI to broadcast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZecSignedSummary {
    /// Network.
    pub network: ZecNetwork,
    /// Raw bytes.
    pub raw: Vec<u8>,
    /// Txid (internal order).
    pub txid: [u8; 32],
}

/// Why signing stopped (nothing was signed, or nothing signed was kept).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZecSignFailure {
    /// Journal rule (corrupt entry, one in flight, full).
    Blocked(ZecJournalBlock),
    /// Signing or post-sign verification.
    Sign(ZecSignError),
    /// The card step failed.
    Card(crate::yubikey::CardJobError),
    /// The journal could not be written (the signature was dropped).
    JournalWrite,
}

/// Fixed texts of the Zcash key-worker jobs (spec/12 §10, spec/14).
pub mod text {
    yw_core::texts! {
        JOURNAL_WRITE = "거래 저널을 쓰지 못해 서명을 버렸습니다. 아무것도 보내지 않았습니다."
            / "The transaction journal could not be written, so the signature was dropped. Nothing was sent.";
        HARDWARE_KEY = "YubiKey 키는 등록된 슬롯에서 가져옵니다."
            / "A YubiKey key is taken from its enrolled slot.";
        IMPORTED_KEY = "가져온 키는 그 키의 목록에서 고릅니다."
            / "An imported key is chosen from its list.";
    }
}

impl ZecSignFailure {
    /// The fixed text in `lang`.
    #[must_use]
    pub fn text_in(&self, lang: Lang) -> String {
        match self {
            Self::Blocked(block) => block.text_in(lang).to_owned(),
            Self::Sign(error) => error.text_in(lang),
            Self::Card(error) => error.text_in(lang),
            Self::JournalWrite => text::JOURNAL_WRITE.get(lang).to_owned(),
        }
    }
}

/// A Zcash key-worker outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZecKeyOutcome {
    /// [`ZecKeyJob::PublicKey`] finished.
    PublicKey(Result<ZecAccount, String>),
    /// A signing job finished.
    Signed(Result<ZecSignedSummary, ZecSignFailure>),
    /// A transition was applied and committed (`Some(state)` when a record changed; `None`:
    /// nothing to write).
    Journal {
        /// Txid.
        txid: [u8; 32],
        /// New state.
        state: Option<ZecTxState>,
    },
    /// A transition changed the record but could not be written: the journal on disk is as
    /// before, so nothing may be sent on it (a `Disclose` must be committed before
    /// `sendrawtransaction`, spec/12 §10.1); the next refresh tries again.
    JournalFailed {
        /// Txid.
        txid: [u8; 32],
    },
}

impl ZecKeyOutcome {
    /// A signing result (accepted across a lock, like the other chains' signed results).
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        matches!(self, Self::Signed(_))
    }
}

/// The public key of a vault source (errors in `lang`).
fn public_key(
    lang: Lang,
    vault: &Vault,
    network: ZecNetwork,
    source: ZecKeySource,
) -> Result<ZecAccount, String> {
    let pubkey = match source {
        ZecKeySource::Derived { account, index } => vault
            .zec_public_key(network == ZecNetwork::Testnet, account, index)
            .map_err(|error| error.text_in(lang))?,
        // An added mnemonic's standard key (spec/02 §8.6).
        ZecKeySource::Mnemonic {
            mnemonic,
            account,
            index,
        } => vault
            .zec_public_key_of(
                Some(mnemonic),
                network == ZecNetwork::Testnet,
                account,
                index,
            )
            .map_err(|error| error.text_in(lang))?,
        ZecKeySource::EvmShared { evm_index } => {
            let index = yw_core::bip32::path::AccountIndex::new(evm_index)
                .map_err(|error| error.text_in(lang))?;
            vault
                .evm_public_key(index)
                .map_err(|error| error.text_in(lang))?
        }
        ZecKeySource::Hardware { .. } => {
            return Err(text::HARDWARE_KEY.get(lang).to_owned());
        }
        ZecKeySource::Imported => {
            return Err(text::IMPORTED_KEY.get(lang).to_owned());
        }
    };
    Ok(ZecAccount {
        network,
        source,
        pubkey,
    })
}

/// The signing step: the vault's `sign_plan`, or the card path.
pub type ZecSigner<'a> =
    dyn FnMut(&Vault, Approved, &ZecPlan) -> Result<ZecSignedTx, ZecSignFailure> + 'a;

impl JournalState {
    /// [`ZecKeyJob::PublicKey`] (errors in the journal's language).
    #[must_use]
    pub fn zec_public_key(
        &self,
        vault: &Vault,
        network: ZecNetwork,
        source: ZecKeySource,
    ) -> Vec<KeyOutcome> {
        vec![KeyOutcome::Zec(Box::new(ZecKeyOutcome::PublicKey(
            public_key(self.lang, vault, network, source),
        )))]
    }

    /// Signs with the vault ([`JournalState::sign_zec_with`]).
    pub fn sign_zec(
        &mut self,
        vault: &mut Vault,
        approved: Box<Approved>,
        plan: &ZecPlan,
        now_unix_ms: u64,
    ) -> Vec<KeyOutcome> {
        self.sign_zec_with(
            vault,
            approved,
            plan,
            now_unix_ms,
            &mut |vault, approved, plan| {
                yw_core::zec::sign_plan(vault, approved, plan).map_err(ZecSignFailure::Sign)
            },
        )
    }

    /// Journal checks (no corrupt ZEC entry, no record of the account that may still confirm,
    /// room), the signing step (which ends with the post-sign verification), the `Signed`
    /// record committed — only then is the transaction returned. A failed write drops it.
    pub fn sign_zec_with(
        &mut self,
        vault: &mut Vault,
        approved: Box<Approved>,
        plan: &ZecPlan,
        now_unix_ms: u64,
        sign_step: &mut ZecSigner<'_>,
    ) -> Vec<KeyOutcome> {
        let mut out = Vec::new();
        let result = (|| {
            let current = self
                .current(vault)
                .map_err(|_| ZecSignFailure::JournalWrite)?;
            check_plan_allowed(&current, &plan.account).map_err(ZecSignFailure::Blocked)?;
            let signed = sign_step(vault, *approved, plan)?;
            let record = ZecRecord::new_signed(plan, &signed, now_unix_ms);
            let mut next = current;
            push_record(&mut next, &record)
                .map_err(|_| ZecSignFailure::Blocked(ZecJournalBlock::Full))?;
            let bytes = next.encode().map_err(|_| ZecSignFailure::JournalWrite)?;
            if vault.save_sidecar(FileKind::Journal, &bytes).is_err() {
                // The write may have landed anyway: a record on disk will be resumed (sent) at
                // the next refresh, so it is reported as written only when it is there.
                let on_disk = vault
                    .open_sidecar(FileKind::Journal)
                    .ok()
                    .flatten()
                    .and_then(|(_, bytes)| {
                        yw_core::journal::JournalPlain::decode(bytes.expose()).ok()
                    })
                    .filter(|plain| {
                        yw_core::journal::zec::ZecEntries::from_plain(plain)
                            .records()
                            .contains(&record)
                    });
                let Some(on_disk) = on_disk else {
                    logging::warn("journal", "journal.zec_signed_write_failed", &[]);
                    return Err(ZecSignFailure::JournalWrite);
                };
                next = on_disk;
            }
            logging::info(
                "journal",
                "journal.zec_signed",
                &[("net", Field::Net(NetworkId::Zcash(plan.account.network)))],
            );
            out.push(KeyOutcome::Journal(Ok(view_of(&next))));
            self.plain = Some(next);
            Ok(ZecSignedSummary {
                network: plan.account.network,
                raw: signed.raw,
                txid: signed.txid,
            })
        })();
        out.insert(0, KeyOutcome::Zec(Box::new(ZecKeyOutcome::Signed(result))));
        out
    }

    /// Applies `transition` to `txid` and commits when a record changed. The UI hears
    /// [`ZecKeyOutcome::Journal`] only once the change is on disk (or nothing needed writing);
    /// a failed write answers [`ZecKeyOutcome::JournalFailed`] instead, so a `Disclose` that
    /// did not land never leads to a send.
    pub fn apply_zec(
        &mut self,
        vault: &mut Vault,
        txid: [u8; 32],
        transition: ZecTransition,
    ) -> Vec<KeyOutcome> {
        let mut next = match self.current(vault) {
            Ok(plain) => plain,
            Err(error) => return vec![KeyOutcome::Journal(Err(error))],
        };
        let state = apply(&mut next, &txid, transition);
        let applied = KeyOutcome::Zec(Box::new(ZecKeyOutcome::Journal { txid, state }));
        if state.is_none() {
            return vec![applied];
        }
        let written = next
            .encode()
            .map_err(|_| {
                yw_core::error::VaultError::Storage(yw_core::error::StorageError::TooLarge)
            })
            .and_then(|bytes| vault.save_sidecar(FileKind::Journal, &bytes));
        match written {
            Ok(_) => {
                logging::info(
                    "journal",
                    "journal.zec_transition",
                    &[("state", Field::Word(state.map_or("-", ZecTxState::name)))],
                );
                let view = view_of(&next);
                self.plain = Some(next);
                vec![applied, KeyOutcome::Journal(Ok(view))]
            }
            Err(error) => {
                logging::warn("journal", "journal.write_failed", &[]);
                vec![
                    KeyOutcome::Zec(Box::new(ZecKeyOutcome::JournalFailed { txid })),
                    KeyOutcome::Journal(Err(error)),
                ]
            }
        }
    }
}
