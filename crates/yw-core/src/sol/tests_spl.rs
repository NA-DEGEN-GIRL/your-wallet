//! v1.1 SPL tests (spec/07 §8.3–§8.4, §9, §13–§14, §17.3–§17.4; spec/09 §3.9, SOL-N2): the
//! `T_SPL` golden (message, signature, transaction), the strict parser's rejection of everything
//! outside the template (allowlist, pinned decimals and program, ATA derivation, off-curve
//! owner, groups, instruction shapes, every bit flip), signing with the test vault, the intent
//! transcript fields, the approval display (`0x0502`/`0x0503` rent display, `L08`), and the
//! journal record (526-byte body, activity `asset` = mint).

use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

use super::address::{
    ATA_PROGRAM, COMPUTE_BUDGET_PROGRAM, SYSTEM_PROGRAM, SolAddress, SolCluster, TOKEN_PROGRAM,
    grouped,
};
use super::display::{
    L08, SimSummary, SolPreviewFacts, SplPreviewFacts, build_sol_transfer_request, max_sol_debit,
    transfer_title,
};
use super::fee::max_fee;
use super::intent::{SolTransferIntent, flags};
use super::message::{
    CompiledIx, SolParseError, assemble_transaction, encode_legacy_message, encode_message,
    parse_identical, parse_message, parse_transaction,
};
use super::recipient::{AccountClass, check_recipient};
use super::sign::sign_transfer;
use super::template::{
    SPL_ALLOWLIST, SolAsset, SolTransferCore, SplAccounts, SplAllowEntry, T_SPL_MESSAGE_LEN,
    T_SPL_TX_LEN, set_compute_unit_limit_data, set_compute_unit_price_data, transfer_checked_data,
};
use super::tests::ABOUT;
use crate::approval::{ApprovalStore, DisplayError, FieldKey};
use crate::bip32::path::AccountIndex;
use crate::codec::base58::base58_encode;
use crate::hex;
use crate::journal::sol::{SOL_JOURNAL_HEADER_LEN, SolRecord, SolRecordError, activity_row};
use crate::slip10::SolKeySource;
use crate::vault::tests::unlocked_with;

const STANDARD0_SECRET: &str = "37df573b3ac4ad5b522e064e25b63ea16bcbe79d449e81a0268d1047948bb445";
const FROM: &str = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
const TO: &str = "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb";
const FROM_ATA: &str = "5N3f1tj9v1vc5TUZ8S7mCAnVmjVKrfnzXWhxLaxyZAgt";
const TO_ATA: &str = "8X8ts1CnpZmtqApE2rREA97xEJuSRcomPGVcMFdS2cgY";
const BLOCKHASH: [u8; 32] = [7; 32];
const RENT165: u64 = 2_039_280;

/// Token-2022 (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`), never allowed.
fn token_2022() -> SolAddress {
    addr("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
}

/// A mint that is on no allowlist.
static FAKE_MINT: SplAllowEntry = SplAllowEntry {
    cluster: SolCluster::Mainnet,
    symbol: "USDC",
    mint: SolAddress::from_bytes([0x55; 32]),
    decimals: 6,
    token_program: TOKEN_PROGRAM,
};

/// Mainnet USDC with other decimals (what a lying RPC would report).
static USDC_9: SplAllowEntry = SplAllowEntry {
    decimals: 9,
    ..SPL_ALLOWLIST[0]
};

/// Mainnet USDC under Token-2022.
static USDC_2022: SplAllowEntry = SplAllowEntry {
    token_program: SolAddress::from_bytes([
        0x06, 0xdd, 0xf6, 0xe1, 0xee, 0x75, 0x8f, 0xde, 0x18, 0x42, 0x5d, 0xbc, 0xe4, 0x6c, 0xcd,
        0xda, 0xb6, 0x1a, 0xfc, 0x4d, 0x83, 0xb9, 0x0d, 0x27, 0xfe, 0xbd, 0xf9, 0x28, 0xd8, 0xa1,
        0x8b, 0xfc,
    ]),
    ..SPL_ALLOWLIST[0]
};

fn addr(text: &str) -> SolAddress {
    SolAddress::parse(text).unwrap()
}

fn usdc() -> SolAsset {
    SolAsset::Spl(&SPL_ALLOWLIST[0])
}

/// The spec/07 §17.3 `T_SPL` golden core (USDC, 1,000,000 raw, `cu_limit` 40,000, price 1,000).
fn golden_core() -> SolTransferCore {
    SolTransferCore {
        from: addr(FROM),
        to: addr(TO),
        asset: usdc(),
        amount: 1_000_000,
        cu_limit: 40_000,
        cu_price_micro: 1_000,
    }
}

/// The golden keys in message order and its instructions, written out from spec/07 §17.3.
fn golden_parts() -> (Vec<[u8; 32]>, Vec<CompiledIx>) {
    let keys = [
        FROM,
        FROM_ATA,
        TO_ATA,
        "11111111111111111111111111111111",
        "ComputeBudget111111111111111111111111111111",
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        TO,
    ]
    .iter()
    .map(|text| addr(text).to_bytes())
    .collect();
    let ixs = vec![
        CompiledIx {
            program: 4,
            accounts: vec![],
            data: hex::decode("02409c0000").unwrap(),
        },
        CompiledIx {
            program: 4,
            accounts: vec![],
            data: hex::decode("03e803000000000000").unwrap(),
        },
        CompiledIx {
            program: 6,
            accounts: vec![0, 2, 8, 7, 3, 5],
            data: vec![1],
        },
        CompiledIx {
            program: 5,
            accounts: vec![1, 7, 2, 0],
            data: hex::decode("0c40420f000000000006").unwrap(),
        },
    ];
    (keys, ixs)
}

fn rebuild(header: [u8; 3], keys: &[[u8; 32]], ixs: &[CompiledIx]) -> Vec<u8> {
    encode_legacy_message(header, keys, &BLOCKHASH, ixs)
}

fn golden_message() -> Vec<u8> {
    let (keys, ixs) = golden_parts();
    rebuild([1, 0, 6], &keys, &ixs)
}

fn parse(msg: &[u8]) -> Result<(SolTransferCore, [u8; 32]), SolParseError> {
    parse_message(msg, SolCluster::Mainnet)
}

#[test]
fn ata_derivation_of_the_golden() {
    let accounts = SplAccounts::of(&golden_core()).unwrap();
    assert_eq!(accounts.from_ata, addr(FROM_ATA));
    assert_eq!(accounts.to_ata, addr(TO_ATA));
    assert!(
        SplAccounts::of(&SolTransferCore {
            asset: SolAsset::Sol,
            ..golden_core()
        })
        .is_none()
    );
}

#[test]
fn t_spl_golden() {
    let message = encode_message(&golden_core(), &BLOCKHASH);
    assert_eq!(message.len(), T_SPL_MESSAGE_LEN);
    assert_eq!(message, golden_message());
    assert_eq!(
        hex::encode(&Sha256::digest(&message)),
        "db305edc2a3c1a3bcde2ac525684340d7a56a8e816c41e86d8231f795ca6d9e8"
    );
    let key = SigningKey::from_bytes(&hex::decode(STANDARD0_SECRET).unwrap().try_into().unwrap());
    let signature = key.sign(&message).to_bytes();
    assert_eq!(
        base58_encode(&signature),
        "5iVhrE6aU2jjv4CyoJKYkqAd3xpPcdPynaGWW32yt6daMUZm1jAdVWq4aSyFNpB4eyU2SGhB6p7tB8eLrMdoGt8L"
    );
    let tx = assemble_transaction(&signature, &message);
    assert_eq!(tx.len(), T_SPL_TX_LEN);
    assert_eq!(
        hex::encode(&Sha256::digest(&tx)),
        "46315e8842900c9dc7f7fab61f0ed80b71ff5c6b622bdf157b6986acccf95e7f"
    );
    assert_eq!(max_fee(40_000, 1_000), Ok(5_040));
    let (core, blockhash, parsed_signature) = parse_transaction(&tx, SolCluster::Mainnet).unwrap();
    assert_eq!(
        (core, blockhash, parsed_signature),
        (golden_core(), BLOCKHASH, signature)
    );
    assert_eq!(
        parse_identical(&message, SolCluster::Mainnet).unwrap().0,
        golden_core()
    );
    // The same bytes on devnet: the mainnet mint is not on the devnet allowlist.
    assert_eq!(
        parse_message(&message, SolCluster::Devnet),
        Err(SolParseError::NotAllowlisted)
    );
    // Devnet USDC round trip.
    let devnet = SolTransferCore {
        asset: SolAsset::Spl(&SPL_ALLOWLIST[2]),
        ..golden_core()
    };
    let bytes = encode_message(&devnet, &BLOCKHASH);
    assert_eq!(bytes.len(), T_SPL_MESSAGE_LEN);
    assert_eq!(
        parse_identical(&bytes, SolCluster::Devnet).unwrap(),
        (devnet, BLOCKHASH)
    );
    assert_eq!(
        parse_message(&bytes, SolCluster::Mainnet),
        Err(SolParseError::NotAllowlisted)
    );
}

/// SOL-N2 for `T_SPL`: instruction shape, programs, header, keys and groups.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one rejection table per template rule"
)]
fn t_spl_parser_rejects_shapes_programs_and_groups() {
    let (keys, ixs) = golden_parts();
    assert!(parse(&rebuild([1, 0, 6], &keys, &ixs)).is_ok());
    // Instruction added / removed / reordered.
    let mut more = ixs.clone();
    more.push(ixs[3].clone());
    assert_eq!(
        parse(&rebuild([1, 0, 6], &keys, &more)),
        Err(SolParseError::UnknownTemplate)
    );
    assert_eq!(
        parse(&rebuild([1, 0, 6], &keys, &ixs[..3])),
        Err(SolParseError::UnknownTemplate)
    );
    let swapped = vec![
        ixs[0].clone(),
        ixs[1].clone(),
        ixs[3].clone(),
        ixs[2].clone(),
    ];
    assert_eq!(
        parse(&rebuild([1, 0, 6], &keys, &swapped)),
        Err(SolParseError::UnexpectedProgram)
    );
    let price_first = vec![
        ixs[1].clone(),
        ixs[0].clone(),
        ixs[2].clone(),
        ixs[3].clone(),
    ];
    assert_eq!(
        parse(&rebuild([1, 0, 6], &keys, &price_first)),
        Err(SolParseError::BadData)
    );
    // ComputeBudget twice.
    let twice = vec![
        ixs[0].clone(),
        ixs[0].clone(),
        ixs[2].clone(),
        ixs[3].clone(),
    ];
    assert_eq!(
        parse(&rebuild([1, 0, 6], &keys, &twice)),
        Err(SolParseError::BadData)
    );
    // Program ids changed: ATA → Token-2022, Token → Token-2022.
    for position in [6, 5] {
        let mut other = keys.clone();
        other[position] = token_2022().to_bytes();
        assert_eq!(
            parse(&rebuild([1, 0, 6], &other, &ixs)),
            Err(SolParseError::UnexpectedProgram),
            "{position}"
        );
    }
    // Header values.
    for header in [
        [1, 0, 2],
        [1, 0, 5],
        [1, 0, 7],
        [1, 1, 6],
        [2, 0, 6],
        [0, 0, 6],
    ] {
        let parsed = parse(&rebuild(header, &keys, &ixs));
        assert!(parsed.is_err(), "{header:?}");
        if header != [1, 0, 2] {
            assert_eq!(parsed, Err(SolParseError::UnknownTemplate), "{header:?}");
        }
    }
    // Duplicate key.
    let mut dup = keys.clone();
    dup[2] = dup[1];
    assert_eq!(
        parse(&rebuild([1, 0, 6], &dup, &ixs)),
        Err(SolParseError::DuplicateKey)
    );
    // Writable group out of order (the two ATAs swapped, indices adjusted).
    let mut writable_swapped = keys.clone();
    writable_swapped.swap(1, 2);
    let remap = |ix: &CompiledIx, a: u8, b: u8| CompiledIx {
        program: if ix.program == a {
            b
        } else if ix.program == b {
            a
        } else {
            ix.program
        },
        accounts: ix
            .accounts
            .iter()
            .map(|index| match *index {
                i if i == a => b,
                i if i == b => a,
                i => i,
            })
            .collect(),
        data: ix.data.clone(),
    };
    let adjusted: Vec<CompiledIx> = ixs.iter().map(|ix| remap(ix, 1, 2)).collect();
    assert_eq!(
        parse(&rebuild([1, 0, 6], &writable_swapped, &adjusted)),
        Err(SolParseError::BadGroupOrder)
    );
    // Readonly group out of order (System and ComputeBudget swapped, indices adjusted).
    let mut readonly_swapped = keys.clone();
    readonly_swapped.swap(3, 4);
    let adjusted: Vec<CompiledIx> = ixs.iter().map(|ix| remap(ix, 3, 4)).collect();
    assert_eq!(
        parse(&rebuild([1, 0, 6], &readonly_swapped, &adjusted)),
        Err(SolParseError::BadGroupOrder)
    );
    // A token account moved into the readonly group (from_ata ↔ recipient wallet).
    let mut role_swapped = keys.clone();
    role_swapped.swap(1, 8);
    let adjusted: Vec<CompiledIx> = ixs.iter().map(|ix| remap(ix, 1, 8)).collect();
    assert_eq!(
        parse(&rebuild([1, 0, 6], &role_swapped, &adjusted)),
        Err(SolParseError::BadGroupOrder)
    );
    // Versioned prefixes and trailing bytes.
    for prefix in [0x80_u8, 0x81] {
        let mut versioned = vec![prefix];
        versioned.extend_from_slice(&golden_message());
        assert_eq!(parse(&versioned), Err(SolParseError::Versioned));
    }
    let mut trailing = golden_message();
    trailing.push(0);
    assert_eq!(parse(&trailing), Err(SolParseError::TrailingBytes));
}

/// SOL-N2 for `T_SPL`: instruction accounts and data.
#[test]
fn t_spl_parser_rejects_accounts_and_data() {
    let (keys, ixs) = golden_parts();
    let with = |index: usize, change: &dyn Fn(&mut CompiledIx)| {
        let mut changed = ixs.clone();
        change(&mut changed[index]);
        parse(&rebuild([1, 0, 6], &keys, &changed))
    };
    // ATA Create (non-idempotent `00`), extra data, empty data.
    assert_eq!(
        with(2, &|ix| ix.data = vec![0]),
        Err(SolParseError::BadData)
    );
    assert_eq!(
        with(2, &|ix| ix.data = vec![1, 0]),
        Err(SolParseError::BadData)
    );
    assert_eq!(with(2, &|ix| ix.data = vec![]), Err(SolParseError::BadData));
    // Token Transfer (tag 3, no decimals) and other TransferChecked lengths.
    assert_eq!(
        with(3, &|ix| ix.data =
            hex::decode("0340420f0000000000").unwrap()),
        Err(SolParseError::BadData)
    );
    assert_eq!(with(3, &|ix| ix.data.push(0)), Err(SolParseError::BadData));
    // Account lists: payer not the signer, System replaced, Token account ≠ the Token program,
    // missing or extra accounts.
    assert_eq!(
        with(2, &|ix| ix.accounts[0] = 1),
        Err(SolParseError::BadAccounts)
    );
    assert_eq!(
        with(2, &|ix| ix.accounts[4] = 4),
        Err(SolParseError::BadAccounts)
    );
    assert_eq!(
        with(2, &|ix| ix.accounts[5] = 6),
        Err(SolParseError::BadAccounts)
    );
    assert_eq!(
        with(2, &|ix| ix.accounts.truncate(5)),
        Err(SolParseError::BadAccounts)
    );
    assert_eq!(
        with(2, &|ix| ix.accounts.push(0)),
        Err(SolParseError::BadAccounts)
    );
    // TransferChecked: owner not the signer, destination ≠ the created ATA, mint differs.
    assert_eq!(
        with(3, &|ix| ix.accounts[3] = 8),
        Err(SolParseError::BadAccounts)
    );
    assert_eq!(
        with(3, &|ix| ix.accounts[2] = 1),
        Err(SolParseError::BadAccounts)
    );
    assert_eq!(
        with(3, &|ix| ix.accounts[1] = 8),
        Err(SolParseError::BadAccounts)
    );
    assert_eq!(
        with(3, &|ix| ix.accounts.truncate(3)),
        Err(SolParseError::BadAccounts)
    );
    // Source = destination (from_ata index replaced by to_ata).
    assert_eq!(
        with(3, &|ix| ix.accounts[0] = 2),
        Err(SolParseError::BadGroupOrder)
    );
    // Index out of range.
    assert_eq!(
        with(3, &|ix| ix.accounts[0] = 9),
        Err(SolParseError::BadIndex)
    );
    assert_eq!(with(2, &|ix| ix.program = 9), Err(SolParseError::BadIndex));
}

/// SOL-N2 for `T_SPL`: allowlist, pinned decimals and program, ATA derivation, off-curve owner,
/// values.
#[test]
fn t_spl_parser_rejects_values_outside_the_allowlist() {
    let with_asset = |entry: &'static SplAllowEntry| {
        parse(&encode_message(
            &SolTransferCore {
                asset: SolAsset::Spl(entry),
                ..golden_core()
            },
            &BLOCKHASH,
        ))
    };
    assert_eq!(with_asset(&FAKE_MINT), Err(SolParseError::NotAllowlisted));
    // Decimals other than the pinned 6 (as a lying RPC would report): refused.
    assert_eq!(with_asset(&USDC_9), Err(SolParseError::NotAllowlisted));
    assert_eq!(
        with_asset(&USDC_2022),
        Err(SolParseError::UnexpectedProgram)
    );
    // ATA mismatch: either token account replaced by another address in the same group order.
    let (keys, ixs) = golden_parts();
    for position in [1, 2] {
        let mut other = keys.clone();
        other[position][31] ^= 1;
        assert_eq!(
            parse(&rebuild([1, 0, 6], &other, &ixs)),
            Err(SolParseError::AtaMismatch),
            "{position}"
        );
    }
    // Off-curve recipients (an ATA pasted as the wallet) and small-order points.
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    for to in [addr(TO_ATA), SolAddress::from_bytes(identity)] {
        let core = SolTransferCore {
            to,
            ..golden_core()
        };
        assert_eq!(
            parse(&encode_message(&core, &BLOCKHASH)),
            Err(SolParseError::RecipientOffCurve),
            "{to}"
        );
    }
    // Self-send: from_ata = to_ata (duplicate keys).
    let selfsend = SolTransferCore {
        to: addr(FROM),
        ..golden_core()
    };
    assert_eq!(
        parse(&encode_message(&selfsend, &BLOCKHASH)),
        Err(SolParseError::DuplicateKey)
    );
    // Amount 0, compute-unit limits.
    let zero = SolTransferCore {
        amount: 0,
        ..golden_core()
    };
    assert_eq!(
        parse(&encode_message(&zero, &BLOCKHASH)),
        Err(SolParseError::ZeroAmount)
    );
    for cu_limit in [0, 1_400_001] {
        let core = SolTransferCore {
            cu_limit,
            ..golden_core()
        };
        assert_eq!(
            parse(&encode_message(&core, &BLOCKHASH)),
            Err(SolParseError::BadComputeLimit)
        );
    }
    let max = SolTransferCore {
        amount: u64::MAX,
        cu_limit: 1_400_000,
        ..golden_core()
    };
    assert_eq!(parse(&encode_message(&max, &BLOCKHASH)).unwrap().0, max);
    // Signature counts.
    let tx = assemble_transaction(&[1; 64], &golden_message());
    for count in [0_u8, 2] {
        let mut bad = tx.clone();
        bad[0] = count;
        assert_eq!(
            parse_transaction(&bad, SolCluster::Mainnet),
            Err(SolParseError::BadSignatureCount)
        );
    }
    for len in 0..tx.len() {
        assert!(
            parse_transaction(&tx[..len], SolCluster::Mainnet).is_err(),
            "{len}"
        );
    }
}

/// SOL-N2: every single-bit flip of the 372-byte message is rejected or parses to something
/// else than the approved (core, blockhash).
#[test]
fn t_spl_every_bit_flip_is_rejected_or_differs() {
    let message = golden_message();
    let mut rejected = 0;
    for index in 0..message.len() {
        for bit in 0..8 {
            let mut flipped = message.clone();
            flipped[index] ^= 1 << bit;
            match parse(&flipped) {
                Err(_) => rejected += 1,
                Ok((core, blockhash)) => assert!(
                    core != golden_core() || blockhash != BLOCKHASH,
                    "{index}:{bit}"
                ),
            }
        }
    }
    assert!(rejected > 2_000, "{rejected}");
}

fn spl_intent(core: SolTransferCore, cluster: SolCluster, flags: u8) -> SolTransferIntent {
    SolTransferIntent {
        id: [0x24; 16],
        cluster,
        source: SolKeySource::Standard(AccountIndex::ZERO),
        core,
        max_fee_lamports: max_fee(core.cu_limit, core.cu_price_micro).unwrap(),
        fee_cap_lamports: 100_000,
        flags,
        created_at_ms: 1_790_000_000_000,
    }
}

fn spl_facts(intent: &SolTransferIntent, to_ata_exists: bool) -> SolPreviewFacts {
    SolPreviewFacts {
        account_label: "Solana 1".to_owned(),
        recipient: check_recipient(&intent.core.to.to_base58(), &intent.core.from, &[]).unwrap(),
        recipient_account: AccountClass::Missing,
        balance: 10_000_000,
        rent0: 890_880,
        rpc_fee: Some(intent.max_fee_lamports),
        simulation: SimSummary::Ok { units: 30_000 },
        spl: Some(SplPreviewFacts {
            token_balance: Some(5_000_000),
            to_ata_exists,
            rent165: RENT165,
        }),
        blocks: Vec::new(),
    }
}

#[test]
fn spl_signing_reproduces_the_golden_and_journals_526_bytes() {
    let vault = unlocked_with(ABOUT);
    let intent = spl_intent(golden_core(), SolCluster::Mainnet, flags::FIRST_TIME);
    let draft = build_sol_transfer_request(
        &intent,
        &SolCluster::Mainnet.genesis(),
        &spl_facts(&intent, false),
    )
    .unwrap();
    let mut store = ApprovalStore::new();
    let request = store.issue(draft, 1_000, intent.created_at_ms).unwrap();
    let approved = store.consume(request.id, request.digest, 2_000).unwrap();
    let signed = sign_transfer(&vault, approved, 2_000, BLOCKHASH, 3_000).unwrap();
    assert_eq!(
        base58_encode(&signed.signature),
        "5iVhrE6aU2jjv4CyoJKYkqAd3xpPcdPynaGWW32yt6daMUZm1jAdVWq4aSyFNpB4eyU2SGhB6p7tB8eLrMdoGt8L"
    );
    assert_eq!(
        hex::encode(&Sha256::digest(&signed.tx)),
        "46315e8842900c9dc7f7fab61f0ed80b71ff5c6b622bdf157b6986acccf95e7f"
    );
    // Journal record: body 89 + 437 = 526 bytes, full load-time validation.
    let record = SolRecord::new_pending(&intent, &signed, 1_790_000_000_500, 1_234);
    let body = record.encode().unwrap();
    assert_eq!(body.len(), SOL_JOURNAL_HEADER_LEN + T_SPL_TX_LEN);
    assert_eq!(body.len(), 526);
    assert_eq!(SolRecord::decode(&body), Ok(record.clone()));
    assert_eq!(record.core(), Some(golden_core()));
    // The cluster byte decides the allowlist: the same transaction filed under devnet is damaged.
    let mut devnet = body.clone();
    devnet[3] = SolCluster::Devnet.code();
    assert_eq!(
        SolRecord::decode(&devnet),
        Err(SolRecordError::Tx(SolParseError::NotAllowlisted))
    );
    // A flipped decimals byte (last message byte of TransferChecked) breaks the record.
    let decimals_at = body.len() - 1;
    let mut decimals = body.clone();
    decimals[decimals_at] = 9;
    assert_eq!(
        SolRecord::decode(&decimals),
        Err(SolRecordError::Tx(SolParseError::NotAllowlisted))
    );
    let mut amount = body.clone();
    amount[decimals_at - 3] ^= 1;
    assert_eq!(SolRecord::decode(&amount), Err(SolRecordError::Signature));
    // Activity row: asset = mint, amount = raw units, counterparty = the wallet (not the ATA).
    let mut landed = record;
    landed.state = crate::journal::sol::SolTxState::Landed;
    landed.terminal_slot = 9;
    let row = activity_row(&landed, 77).unwrap();
    assert_eq!(row.asset, "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
    assert_eq!(row.amount, "1000000");
    assert_eq!(row.counterparty, TO);
    assert_eq!(row.account, FROM);
    assert_eq!(row.title, "[Solana mainnet] 토큰 전송: 1.000000 USDC");
    assert_eq!(row.status, "succeeded");
}

#[test]
fn spl_intent_transcript_binds_the_token_fields() {
    let base = spl_intent(golden_core(), SolCluster::Mainnet, 0);
    let transcript = base.transcript();
    let find = |needle: &[u8]| {
        transcript
            .windows(needle.len())
            .any(|window| window == needle)
    };
    for bound in [
        addr("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
        TOKEN_PROGRAM,
        addr(FROM_ATA),
        addr(TO_ATA),
    ] {
        let mut needle = 32_u32.to_be_bytes().to_vec();
        needle.extend_from_slice(bound.as_bytes());
        assert!(find(&needle), "{bound}");
    }
    let sol = spl_intent(
        SolTransferCore {
            asset: SolAsset::Sol,
            ..golden_core()
        },
        SolCluster::Mainnet,
        0,
    );
    assert_eq!(transcript.len(), sol.transcript().len() + 4 * 36 + 1);
    let usdt = spl_intent(
        SolTransferCore {
            asset: SolAsset::Spl(&SPL_ALLOWLIST[1]),
            ..golden_core()
        },
        SolCluster::Mainnet,
        0,
    );
    let decimals9 = spl_intent(
        SolTransferCore {
            asset: SolAsset::Spl(&USDC_9),
            ..golden_core()
        },
        SolCluster::Mainnet,
        0,
    );
    for other in [sol, usdt, decimals9] {
        assert_ne!(other.intent_hash(), base.intent_hash());
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "every SPL display field in one place"
)]
fn spl_approval_fields_rent_display_and_send_max() {
    let intent = spl_intent(
        golden_core(),
        SolCluster::Mainnet,
        flags::FIRST_TIME | flags::SEND_MAX,
    );
    let facts = spl_facts(&intent, false);
    let draft =
        build_sol_transfer_request(&intent, &SolCluster::Mainnet.genesis(), &facts).unwrap();
    assert_eq!(
        draft.display.title,
        "[Solana mainnet] 토큰 전송: 1.000000 USDC"
    );
    assert_eq!(
        draft.display.title,
        transfer_title(SolCluster::Mainnet, &golden_core())
    );
    let keys: Vec<u16> = draft
        .display
        .fields
        .iter()
        .map(|field| field.key.0)
        .collect();
    assert_eq!(
        keys,
        [
            0x0001, 0x0002, 0x0003, 0x0501, 0x0502, 0x0503, 0x0504, 0x0505, 0x0506, 0x0507, 0x0508,
            0x0509
        ]
    );
    for field in &draft.display.fields {
        assert!(FieldKey(field.key.0).flags().is_some());
        assert_eq!(field.critical, (0x0001..=0x0505).contains(&field.key.0));
    }
    let value = |key: u16| {
        draft
            .display
            .fields
            .iter()
            .find(|field| field.key.0 == key)
            .unwrap()
            .clone()
    };
    let amount = value(0x0502);
    assert_eq!(amount.sub_label, "USDC");
    for part in [
        "1.000000 USDC".to_owned(),
        "1,000,000 (원시 단위, decimals 6)".to_owned(),
        grouped(&addr("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")),
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_owned(),
        grouped(&addr(FROM_ATA)),
        grouped(&addr(TO_ATA)),
    ] {
        assert!(amount.value.contains(&part), "{part}");
    }
    // Grouped addresses stand on their own lines (bold middle groups, spec/07 §12.3).
    assert!(
        amount
            .value
            .lines()
            .any(|line| line == grouped(&addr(TO_ATA)))
    );
    assert!(value(0x0501).value.starts_with(&grouped(&addr(TO))));
    // Rent display: missing destination ATA → the sender pays rent165.
    let ata = value(0x0503).value;
    assert!(ata.contains("없습니다"), "{ata}");
    assert!(ata.contains("0.002039280 SOL(2,039,280 lamports)"), "{ata}");
    let total = max_sol_debit(&intent, &facts);
    assert_eq!(total, 5_040 + RENT165);
    assert!(value(0x0505).value.contains("2,044,320 lamports"));
    assert!(
        value(0x0506)
            .value
            .contains("5.000000 USDC → 4.000000 USDC")
    );
    // Send max (L08) names the token, not SOL.
    let send_max = draft
        .display
        .warnings
        .iter()
        .find(|warning| warning.rule == L08)
        .unwrap();
    assert!(send_max.text.contains("USDC 잔액은 0"));
    // Existing destination ATA: no rent in the total.
    let existing = spl_facts(&intent, true);
    let draft =
        build_sol_transfer_request(&intent, &SolCluster::Mainnet.genesis(), &existing).unwrap();
    let ata = draft
        .display
        .fields
        .iter()
        .find(|field| field.key.0 == 0x0503)
        .unwrap();
    assert!(ata.value.contains("이미 있습니다"));
    assert_eq!(max_sol_debit(&intent, &existing), 5_040);
    // An SPL intent without SPL preview facts is refused (defensive).
    let mut missing = spl_facts(&intent, false);
    missing.spl = None;
    assert_eq!(
        build_sol_transfer_request(&intent, &SolCluster::Mainnet.genesis(), &missing).unwrap_err(),
        DisplayError::InvalidText
    );
    // The SOL draft has no 0x0503.
    let sol = spl_intent(
        SolTransferCore {
            asset: SolAsset::Sol,
            ..golden_core()
        },
        SolCluster::Mainnet,
        0,
    );
    let mut sol_facts = spl_facts(&sol, false);
    sol_facts.spl = None;
    let draft =
        build_sol_transfer_request(&sol, &SolCluster::Mainnet.genesis(), &sol_facts).unwrap();
    assert!(
        draft
            .display
            .fields
            .iter()
            .all(|field| field.key.0 != 0x0503)
    );
}

#[test]
fn spl_template_instruction_data() {
    assert_eq!(
        set_compute_unit_limit_data(40_000),
        hex::decode("02409c0000").unwrap()
    );
    assert_eq!(
        set_compute_unit_price_data(1_000),
        hex::decode("03e803000000000000").unwrap()
    );
    assert_eq!(
        transfer_checked_data(1_000_000, 6),
        hex::decode("0c40420f000000000006").unwrap()
    );
    // The program constants in the golden keys.
    let (keys, _) = golden_parts();
    assert_eq!(keys[3], SYSTEM_PROGRAM.to_bytes());
    assert_eq!(keys[4], COMPUTE_BUDGET_PROGRAM.to_bytes());
    assert_eq!(keys[5], TOKEN_PROGRAM.to_bytes());
    assert_eq!(keys[6], ATA_PROGRAM.to_bytes());
}
