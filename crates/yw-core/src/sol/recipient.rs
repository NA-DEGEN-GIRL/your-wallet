//! Recipient checks and address-poisoning defence (spec/07 §12.1–§12.2).

use core::fmt;

use super::address::{CurveClass, SolAddress, curve_class, is_blocked_recipient};
use super::template::SolAsset;
use crate::codec::base58::Base58Error;

/// Matching characters at either end that make two addresses lookalikes (observed poisoning
/// addresses match 3 or more at both ends).
pub const SOL_LOOKALIKE_CHARS: usize = 3;

/// A local check that blocks the input (no approval window, spec/07 §13.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecipientBlock {
    /// Not a strict base58 32-byte address.
    Format(Base58Error),
    /// A program, sysvar or allowlisted mint.
    IsProgram,
    /// A small-order or non-canonical curve point.
    Unspendable,
    /// The sending account itself.
    SelfSend,
    /// SPL only: an off-curve recipient (PDA or token account). Its ATA would be owned by an
    /// address nobody can sign for, so the tokens could never move (spec/07 §12.1-6).
    OffCurveOwner,
}

impl fmt::Display for RecipientBlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Format(_) => "주소 형식이 올바르지 않습니다.",
            Self::IsProgram => "받는 주소가 프로그램·시스템·토큰 mint 주소입니다. 보내면 잃습니다.",
            Self::Unspendable => "받는 주소는 아무도 쓸 수 없는 주소입니다. 보내면 잃습니다.",
            Self::SelfSend => "보내는 계정과 같은 주소로는 보낼 수 없습니다.",
            Self::OffCurveOwner => {
                "토큰은 일반 지갑 주소로만 보낼 수 있습니다. 이 주소는 프로그램 소유 주소(PDA)나 토큰 계정이라 받은 토큰을 옮길 수 없습니다."
            }
        })
    }
}

impl std::error::Error for RecipientBlock {}

/// Where a known address comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KnownKind {
    /// Address book (`verified` as stored).
    Book {
        /// User-verified.
        verified: bool,
    },
    /// One of the wallet's Solana accounts (`index` of `m/44'/501'/i'/0'`).
    Own {
        /// Account index.
        index: u32,
    },
    /// One of the wallet's imported Solana keys (spec/02 §8.4).
    OwnImported,
    /// One of the wallet's `YubiKey` Solana accounts (spec/10 §10).
    OwnHardware,
    /// A standard account of one of the wallet's added recovery phrases (spec/02 §8.6).
    OwnMnemonic,
    /// A recipient of an earlier successful send on the same cluster (activity / journal): the
    /// address is known (no `FirstTime`).
    Sent,
    /// Any other address of the sent history — a failed, expired or still pending send, or one
    /// on the other cluster: compared for lookalikes only, it does not make the address known
    /// (spec/07 §12.1-8).
    History,
}

/// A known address with its name (address-book label, account label, or empty for sent).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownAddress {
    /// Address.
    pub address: SolAddress,
    /// Label (already user-entered text).
    pub label: String,
    /// Source.
    pub kind: KnownKind,
}

/// Result of the local checks that let the send continue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientCheck {
    /// Parsed recipient.
    pub to: SolAddress,
    /// Exact address-book / own-account match.
    pub exact: Option<KnownAddress>,
    /// Off-curve (`L02`).
    pub off_curve: bool,
    /// Lookalike known addresses (`L03`).
    pub lookalikes: Vec<KnownAddress>,
    /// Not in the address book, own accounts or sent history (`L06`).
    pub first_time: bool,
}

/// Same first or last [`SOL_LOOKALIKE_CHARS`] base58 characters but a different address.
#[must_use]
pub fn is_lookalike(a: &SolAddress, b: &SolAddress) -> bool {
    if a == b {
        return false;
    }
    let (a, b) = (a.to_base58(), b.to_base58());
    let n = SOL_LOOKALIKE_CHARS;
    let head = |text: &str| text.get(..n).map(str::to_owned);
    let tail = |text: &str| text.get(text.len().saturating_sub(n)..).map(str::to_owned);
    (head(&a).is_some() && head(&a) == head(&b)) || (tail(&a).is_some() && tail(&a) == tail(&b))
}

/// The local checks of spec/07 §12.1 in order (1–4 block; 5–8 annotate).
///
/// # Errors
///
/// [`RecipientBlock`].
pub fn check_recipient(
    input: &str,
    from: &SolAddress,
    known: &[KnownAddress],
) -> Result<RecipientCheck, RecipientBlock> {
    let to = SolAddress::parse_input(input).map_err(RecipientBlock::Format)?;
    if is_blocked_recipient(&to) {
        return Err(RecipientBlock::IsProgram);
    }
    let class = curve_class(to.as_bytes());
    if matches!(class, CurveClass::SmallOrder | CurveClass::NonCanonical) {
        return Err(RecipientBlock::Unspendable);
    }
    if to == *from {
        return Err(RecipientBlock::SelfSend);
    }
    let exact = known
        .iter()
        .find(|entry| {
            entry.address == to
                && matches!(
                    entry.kind,
                    KnownKind::Book { .. }
                        | KnownKind::Own { .. }
                        | KnownKind::OwnImported
                        | KnownKind::OwnHardware
                        | KnownKind::OwnMnemonic
                )
        })
        .cloned();
    let seen = known
        .iter()
        .any(|entry| entry.address == to && entry.kind != KnownKind::History);
    let mut lookalikes: Vec<KnownAddress> = Vec::new();
    for entry in known {
        if is_lookalike(&entry.address, &to)
            && !lookalikes.iter().any(|seen| seen.address == entry.address)
        {
            lookalikes.push(entry.clone());
        }
    }
    Ok(RecipientCheck {
        to,
        exact,
        off_curve: class == CurveClass::OffCurve,
        lookalikes,
        first_time: !seen,
    })
}

/// The local checks for an asset: [`check_recipient`], and for SPL an off-curve recipient is
/// blocked ([`RecipientBlock::OffCurveOwner`]) instead of the SOL high-risk warning `L02`.
///
/// # Errors
///
/// [`RecipientBlock`].
pub fn check_recipient_for(
    input: &str,
    from: &SolAddress,
    known: &[KnownAddress],
    asset: SolAsset,
) -> Result<RecipientCheck, RecipientBlock> {
    let check = check_recipient(input, from, known)?;
    if check.off_curve && matches!(asset, SolAsset::Spl(_)) {
        return Err(RecipientBlock::OffCurveOwner);
    }
    Ok(check)
}

/// `getAccountInfo(to)` classification (spec/07 §12.2; reference only: it may block, never clear
/// a warning).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountClass {
    /// `null`: a new account (rent rule applies).
    Missing,
    /// Owner System, not executable: a normal wallet.
    SystemWallet,
    /// Owner Token or Token-2022: blocked (`RecipientIsTokenAccount`).
    TokenAccount,
    /// Executable: blocked (`RecipientIsProgram`).
    Program,
    /// Any other owner: high risk (`L04`).
    ProgramOwned,
}

/// Classifies an account from its owner and `executable` flag (`None` = account missing).
#[must_use]
pub fn classify_account(info: Option<(&SolAddress, bool)>) -> AccountClass {
    const TOKEN_2022: [u8; 32] = [
        0x06, 0xdd, 0xf6, 0xe1, 0xee, 0x75, 0x8f, 0xde, 0x18, 0x42, 0x5d, 0xbc, 0xe4, 0x6c, 0xcd,
        0xda, 0xb6, 0x1a, 0xfc, 0x4d, 0x83, 0xb9, 0x0d, 0x27, 0xfe, 0xbd, 0xf9, 0x28, 0xd8, 0xa1,
        0x8b, 0xfc,
    ];
    match info {
        None => AccountClass::Missing,
        Some((_, true)) => AccountClass::Program,
        Some((owner, false)) if owner == &super::address::SYSTEM_PROGRAM => {
            AccountClass::SystemWallet
        }
        Some((owner, false))
            if owner == &super::address::TOKEN_PROGRAM || owner.as_bytes() == &TOKEN_2022 =>
        {
            AccountClass::TokenAccount
        }
        Some(_) => AccountClass::ProgramOwned,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AccountClass, KnownAddress, KnownKind, RecipientBlock, check_recipient,
        check_recipient_for, classify_account, is_lookalike,
    };
    use crate::sol::address::{SYSTEM_PROGRAM, SolAddress, TOKEN_PROGRAM};
    use crate::sol::template::SolAsset;

    fn addr(text: &str) -> SolAddress {
        SolAddress::parse(text).unwrap()
    }

    const FROM: &str = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
    const OWN1: &str = "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb";
    const OTHER: &str = "7WktogJEd2wQ9eH2oWusmcoFTgeYi6rS632UviTBJ2jm";

    fn known() -> Vec<KnownAddress> {
        vec![
            KnownAddress {
                address: addr(OWN1),
                label: "계정 2".to_owned(),
                kind: KnownKind::Own { index: 1 },
            },
            KnownAddress {
                address: addr("GjJyeC1r2RgkuoCWMyPYkCWSGSGLcz266EaAkLA27AhL"),
                label: "거래소".to_owned(),
                kind: KnownKind::Book { verified: true },
            },
        ]
    }

    #[test]
    fn blocking_checks_in_order() {
        let from = addr(FROM);
        assert!(matches!(
            check_recipient("0OIl", &from, &[]),
            Err(RecipientBlock::Format(_))
        ));
        assert_eq!(
            check_recipient("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", &from, &[]),
            Err(RecipientBlock::IsProgram)
        );
        assert_eq!(
            check_recipient("11111111111111111111111111111111", &from, &[]),
            Err(RecipientBlock::IsProgram)
        );
        assert_eq!(
            check_recipient("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", &from, &[]),
            Err(RecipientBlock::IsProgram)
        );
        // A small-order point that is not in the blocked list: the identity (0, 1).
        let mut identity = [0_u8; 32];
        identity[0] = 1;
        let identity = SolAddress::from_bytes(identity).to_base58();
        assert_eq!(
            check_recipient(&identity, &from, &[]),
            Err(RecipientBlock::Unspendable)
        );
        assert_eq!(
            check_recipient(FROM, &from, &[]),
            Err(RecipientBlock::SelfSend)
        );
    }

    #[test]
    fn annotations() {
        let from = addr(FROM);
        let own = check_recipient(OWN1, &from, &known()).unwrap();
        assert_eq!(own.exact.unwrap().kind, KnownKind::Own { index: 1 });
        assert!(!own.first_time && !own.off_curve && own.lookalikes.is_empty());
        let fresh = check_recipient(OTHER, &from, &known()).unwrap();
        assert!(fresh.first_time && fresh.exact.is_none());
        let ata =
            check_recipient("5N3f1tj9v1vc5TUZ8S7mCAnVmjVKrfnzXWhxLaxyZAgt", &from, &[]).unwrap();
        assert!(ata.off_curve);
        let sent = vec![KnownAddress {
            address: addr(OTHER),
            label: String::new(),
            kind: KnownKind::Sent,
        }];
        let repeat = check_recipient(OTHER, &from, &sent).unwrap();
        assert!(!repeat.first_time && repeat.exact.is_none());
    }

    #[test]
    fn history_that_did_not_succeed_here_is_not_known_but_is_compared() {
        let from = addr(FROM);
        // A failed / expired / pending send, or one on the other cluster: still a first time.
        let history = vec![KnownAddress {
            address: addr(OTHER),
            label: String::new(),
            kind: KnownKind::History,
        }];
        let again = check_recipient(OTHER, &from, &history).unwrap();
        assert!(again.first_time && again.exact.is_none());
        assert!(
            again.lookalikes.is_empty(),
            "the address itself is no lookalike"
        );
        // …but a lookalike of it is still flagged (L03).
        let poisoned = check_recipient(
            "7WktogJEd2wQ9eH2oWuszcoFTgeYi6rS632UviTBJ2jm",
            &from,
            &history,
        )
        .unwrap();
        assert!(poisoned.first_time);
        assert_eq!(poisoned.lookalikes, history);
    }

    #[test]
    fn spl_blocks_off_curve_recipients() {
        let from = addr(FROM);
        let usdc = SolAsset::Spl(&crate::sol::template::SPL_ALLOWLIST[0]);
        // A USDC ATA pasted as the recipient (off-curve): SOL warns (L02), SPL blocks.
        let ata = "5N3f1tj9v1vc5TUZ8S7mCAnVmjVKrfnzXWhxLaxyZAgt";
        assert!(
            check_recipient_for(ata, &from, &[], SolAsset::Sol)
                .unwrap()
                .off_curve
        );
        assert_eq!(
            check_recipient_for(ata, &from, &[], usdc),
            Err(RecipientBlock::OffCurveOwner)
        );
        // ComputeBudget is off-curve too but the program block comes first.
        assert_eq!(
            check_recipient_for(
                "ComputeBudget111111111111111111111111111111",
                &from,
                &[],
                usdc
            ),
            Err(RecipientBlock::IsProgram)
        );
        // Normal wallets pass for both.
        let ok = check_recipient_for(OTHER, &from, &known(), usdc).unwrap();
        assert!(!ok.off_curve && ok.first_time);
        assert!(check_recipient_for(OWN1, &from, &known(), usdc).is_ok());
    }

    #[test]
    fn lookalike_rule() {
        let base = addr(OTHER);
        let both = addr("7WktogJEd2wQ9eH2oWuszcoFTgeYi6rS632UviTBJ2jm");
        let head = addr("7WktogJEd2wQ9eH2oWusmcoFTgeYi6rS632UviTBJzzz");
        let tail = addr("6WktogJEd2wQ9eH2oWusmcoFTgeYi6rS632UviTBJ2jm");
        let two = addr("7WztogJEd2wQ9eH2oWusmcoFTgeYi6rS632UviTBJzjm");
        assert!(is_lookalike(&base, &both));
        assert!(is_lookalike(&base, &head));
        assert!(is_lookalike(&base, &tail));
        assert!(
            !is_lookalike(&base, &two),
            "2 matching characters are not enough"
        );
        assert!(!is_lookalike(&base, &base));
        let from = addr(FROM);
        let book = vec![KnownAddress {
            address: base,
            label: "친구".to_owned(),
            kind: KnownKind::Book { verified: false },
        }];
        let checked = check_recipient(&both.to_base58(), &from, &book).unwrap();
        assert_eq!(checked.lookalikes.len(), 1);
        assert!(checked.first_time);
        let exact = check_recipient(OTHER, &from, &book).unwrap();
        assert!(exact.lookalikes.is_empty() && !exact.first_time);
        assert_eq!(
            exact.exact.unwrap().kind,
            KnownKind::Book { verified: false }
        );
    }

    #[test]
    fn rpc_classification() {
        let other = addr(OTHER);
        assert_eq!(classify_account(None), AccountClass::Missing);
        assert_eq!(
            classify_account(Some((&SYSTEM_PROGRAM, false))),
            AccountClass::SystemWallet
        );
        assert_eq!(
            classify_account(Some((&TOKEN_PROGRAM, false))),
            AccountClass::TokenAccount
        );
        assert_eq!(
            classify_account(Some((
                &addr("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"),
                false
            ))),
            AccountClass::TokenAccount
        );
        assert_eq!(
            classify_account(Some((&other, true))),
            AccountClass::Program
        );
        assert_eq!(
            classify_account(Some((&other, false))),
            AccountClass::ProgramOwned
        );
    }
}
