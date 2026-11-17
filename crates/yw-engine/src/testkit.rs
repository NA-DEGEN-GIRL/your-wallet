//! Test helpers that the yw-app tests use across the crate boundary (spec/15 §11.4 S2, D-f):
//! `cfg(test)` does not cross crates and dev-dependencies and features are frozen, so these are
//! always compiled but hidden from the docs (the same reason `yw_core::yubikey::mock` and
//! [`crate::yubikey::MockSource`] are always compiled). Production code never names this module:
//! a yw-app unit test (`card_pcsc`) scans its non-test sources for it.
//!
//! (2026-11-17, S2 E3: [`yubikey_wallet`] moved here from the key worker's `cfg(test)` tests
//! module, which the App tests reached as `workers::key::tests::yubikey_wallet` while both were in
//! yw-app; it now takes the folder instead of a tag, because only the caller knows whether the
//! folder is real. There is no raw meta-sidecar writer here: owner decision, the App tests seal
//! raw meta through a second vault session.)

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use yw_core::bip32::path::AccountIndex;
use yw_core::btc::BtcNetwork;
use yw_core::secret::Zeroizing;
use yw_core::yubikey::mock::MockCard;
use yw_core::yubikey::plan::{CardSlot, KeyRole, PgpKey, PivSlot, PlannedSlot};

use crate::events::{KeyJob, KeyOutcome, MetaLoaded};
use crate::workers::key::KeyWorker;
use crate::workers::key::platform::KeyDeps;

/// A worker on the `abandon` wallet with two emulated `YubiKey`s enrolled: card A (SIG = EVM 0,
/// AUT = EVM 1, PIV 82 = Solana 0) and card B (SIG = BIP84 mainnet address 0); both cards stay
/// inserted. Returns the worker, the cards (A, B), the folder and the reconciled meta.
/// `deps` gives the storage and the clock (its card source is replaced by the emulator): the
/// in-memory platform in the key worker's unit tests, the Windows platform on real files (no
/// readers) in the App tests, which read the files in `dir` themselves.
///
/// # Panics
///
/// When a step of the import or the enrolment fails (a test failure).
#[must_use]
#[expect(
    clippy::unwrap_used,
    reason = "test helper (spec/15 §11.4 S2): a failed step is a failed test"
)]
pub fn yubikey_wallet(
    dir: PathBuf,
    deps: KeyDeps,
) -> (KeyWorker, Arc<Mutex<Vec<MockCard>>>, PathBuf, MetaLoaded) {
    let about = format!("{} about", ["abandon"; 11].join(" "));
    let cards = Arc::new(Mutex::new(vec![MockCard::new(7_700_011)]));
    let mut worker =
        KeyWorker::new(&dir, deps).with_card_source(Box::new(crate::yubikey::MockSource {
            cards: Arc::clone(&cards),
        }));
    let bytes = |text: &str| Zeroizing::new(text.as_bytes().to_vec());
    worker.handle(KeyJob::Load);
    worker.handle(KeyJob::PreviewImport {
        password: Some(bytes("yubikey wallet password")),
        phrase: bytes(&about),
        passphrase: None,
    });
    assert!(matches!(
        worker.handle(KeyJob::CommitImport).first(),
        Some(KeyOutcome::Imported(Ok(())))
    ));
    let evm = |index| KeyRole::Evm {
        index: AccountIndex::new(index).unwrap(),
        btc: None,
    };
    let enrol = |worker: &mut KeyWorker, slots| match worker
        .handle(KeyJob::EnrolYubiKey {
            phrase: bytes(&about),
            passphrase: None,
            slots,
            admin_pin: bytes("12345678"),
            management_key: Zeroizing::new(yw_core::yubikey::piv::DEFAULT_MANAGEMENT_KEY.to_vec()),
        })
        .pop()
    {
        Some(KeyOutcome::YubiKeyEnrolled(Ok(_))) => {}
        other => unreachable!("enrolment failed: {other:?}"),
    };
    enrol(
        &mut worker,
        vec![
            PlannedSlot::recommended(CardSlot::OpenPgp(PgpKey::Sig), evm(0)),
            PlannedSlot::recommended(CardSlot::OpenPgp(PgpKey::Aut), evm(1)),
            PlannedSlot::recommended(
                CardSlot::Piv(PivSlot::new(0x82).unwrap()),
                KeyRole::Sol {
                    index: AccountIndex::ZERO,
                },
            ),
        ],
    );
    // Card B alone in the reader for its enrolment, then both inserted.
    let card_a = cards.lock().unwrap().pop().unwrap();
    cards.lock().unwrap().push(MockCard::new(7_700_012));
    enrol(
        &mut worker,
        vec![PlannedSlot::recommended(
            CardSlot::OpenPgp(PgpKey::Sig),
            KeyRole::Btc {
                network: BtcNetwork::Mainnet,
                script: yw_core::btc::ScriptType::P2wpkh,
                index: 0,
            },
        )],
    );
    cards.lock().unwrap().insert(0, card_a);
    for card in cards.lock().unwrap().iter_mut() {
        card.log.clear();
    }
    let Some(KeyOutcome::Meta(Ok(loaded))) = worker.handle(KeyJob::LoadMeta).pop() else {
        unreachable!("meta");
    };
    (worker, cards, dir, loaded)
}
