//! How an address line is drawn (spec/04 §2.6, §3.3): one whole address without spaces, the 4
//! characters after its family's prefix and the last 4 emphasized, as `(text, emphasized)` spans.
//! Every screen, approval window and secret window draws its addresses from these spans (what you
//! see is what you sign: values are never cut, addresses are drawn whole).
//!
//! 2026-11-24 (spec/15 §11.3, §11.4 S5-2): moved here unchanged from yw-app `ui::theme` (the pure
//! span helpers, with their tests), so the shared screen model and every platform cut an address
//! the same way; the painting of the spans (`paint_spans`, GDI) stays in yw-app `ui::theme`.

/// The family of `text` when it is one whole address without spaces: `0x` + 40 hex digits, a
/// Bitcoin address of mainnet or testnet4, a Zcash address or a Solana address.
#[must_use]
pub fn address_kind(text: &str) -> Option<AddressKind> {
    if text.is_empty() || !text.is_ascii() || text.contains(char::is_whitespace) {
        return None;
    }
    if let Some(digits) = text.strip_prefix("0x") {
        return (digits.len() == 40 && digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .then_some(AddressKind::Evm);
    }
    if yw_core::btc::BtcNetwork::ALL
        .into_iter()
        .any(|net| yw_core::btc::parse_address(text, net).is_ok())
    {
        return Some(AddressKind::Bitcoin);
    }
    if yw_core::zec::ZecNetwork::ALL
        .into_iter()
        .any(|net| yw_core::zec::parse_recipient(text, net).is_ok())
    {
        return Some(AddressKind::Zcash);
    }
    yw_core::sol::SolAddress::parse(text)
        .is_ok()
        .then_some(AddressKind::Solana)
}

/// `address` in the 4-character groups the screens drew before 2026-11-12 (EVM: `0x`, then
/// groups of the 40 digits; the others from the first character).
fn grouped_form(address: &str, kind: AddressKind) -> String {
    let (head, rest) = match kind {
        AddressKind::Evm => (
            address.get(..2).unwrap_or(""),
            address.get(2..).unwrap_or(""),
        ),
        AddressKind::Solana | AddressKind::Bitcoin | AddressKind::Zcash => ("", address),
    };
    let mut out = String::with_capacity(address.len().saturating_add(address.len() / 4));
    out.push_str(head);
    for (index, character) in rest.chars().enumerate() {
        if index != 0 && index % 4 == 0 {
            out.push(' ');
        }
        out.push(character);
    }
    out
}

/// `text` as one whole address and its family: the address itself ([`address_kind`]) or that
/// address in exactly the 4-character groups of [`grouped_form`] (the approval display model's
/// EVM addresses, `yw_core::sol::address::grouped`, `yw_engine::text::grouped`), so only an
/// address line is redrawn, never other text with spaces.
#[must_use]
pub fn whole_address(text: &str) -> Option<(String, AddressKind)> {
    if !text.contains(' ') {
        return address_kind(text).map(|kind| (text.to_owned(), kind));
    }
    let joined: String = text.split(' ').collect();
    let kind = address_kind(&joined)?;
    (grouped_form(&joined, kind) == text).then_some((joined, kind))
}

/// A line that is one address ([`whole_address`]) followed by its bracketed notes (the approval
/// display model's `0x… [일반 계정(EOA)] [주소록: A]`): the address part and the notes, so the
/// address is drawn whole on its own line (2026-11-14, spec/04 §3.3; before, the notes kept such
/// a line in its 4-character groups).
#[must_use]
pub fn address_with_notes(text: &str) -> Option<(&str, &str)> {
    let (address, notes) = text.split_once(" [")?;
    whole_address(address)?;
    (!notes.is_empty()).then_some(())?;
    Some((address, text.get(address.len().saturating_add(1)..)?))
}

/// How every address line is drawn (2026-11-12, spec/04 §3.3): the [`own_address_spans`] of
/// [`whole_address`]: the whole address without spaces, the 4 characters after its family's
/// prefix and the last 4 emphasized. `None` for any other text.
#[must_use]
pub fn address_spans(text: &str) -> Option<Vec<(String, bool)>> {
    whole_address(text).map(|(address, kind)| own_address_spans(&address, kind, false))
}

/// The address family of an own-account address line ([`own_address_spans`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressKind {
    /// `0x` + 40 hex (checksum case kept).
    Evm,
    /// Base58, no prefix.
    Solana,
    /// Bech32 (`bc1q`/`bc1p`/`tb1q`/`tb1p`, prefix of 4) or base58 (`1…`/`3…`/`m…`/`n…`/`2…`).
    Bitcoin,
    /// Transparent `t1…`/`t3…` (testnet `tm…`/`t2…`), prefix of 2.
    Zcash,
}

/// Characters emphasized at each end of an own-account address (after the prefix).
pub const OWN_ADDRESS_ENDS: usize = 4;

/// The part of `address` that is a fixed prefix of its family, not emphasized: `0x`, the
/// bech32 `bc1q`·`bc1p`·`tb1q`·`tb1p`, Zcash `t1`·`t3`·`tm`·`t2`; none for base58.
fn own_address_prefix(address: &str, kind: AddressKind) -> usize {
    let starts = |prefix: &str| {
        address
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    };
    match kind {
        AddressKind::Evm if starts("0x") => 2,
        AddressKind::Bitcoin if ["bc1q", "bc1p", "tb1q", "tb1p"].into_iter().any(starts) => 4,
        AddressKind::Zcash if ["t1", "t3", "tm", "t2"].into_iter().any(starts) => 2,
        _ => 0,
    }
}

/// How every address is drawn (the account cards since 2026-11-11, spec/04 §2.6; every screen
/// and approval window since 2026-11-12, §3.3 and [`address_spans`]): the whole address without
/// spaces (case kept), the [`OWN_ADDRESS_ENDS`] characters after the family's prefix and the
/// last [`OWN_ADDRESS_ENDS`] emphasized: `(text, emphasized)` spans. With `short`, the middle is replaced by `…` (`0x0Bd7…AD73`; no screen uses it
/// since the copy lines of 2026-11-11 show every address whole).
/// An address too short to have a middle is one plain span.
#[must_use]
pub fn own_address_spans(address: &str, kind: AddressKind, short: bool) -> Vec<(String, bool)> {
    let prefix = own_address_prefix(address, kind);
    let ends = OWN_ADDRESS_ENDS;
    let chars: Vec<char> = address.chars().collect();
    let total = chars.len();
    if !address.is_ascii()
        || total
            < prefix
                .saturating_add(ends.saturating_mul(2))
                .saturating_add(1)
    {
        return vec![(address.to_owned(), false)];
    }
    let piece =
        |from: usize, to: usize| -> String { address.get(from..to).unwrap_or("").to_owned() };
    let head_end = prefix.saturating_add(ends);
    let tail_start = total.saturating_sub(ends);
    let mut spans = Vec::with_capacity(5);
    if prefix > 0 {
        spans.push((piece(0, prefix), false));
    }
    spans.push((piece(prefix, head_end), true));
    spans.push((
        if short {
            "…".to_owned()
        } else {
            piece(head_end, tail_start)
        },
        false,
    ));
    spans.push((piece(tail_start, total), true));
    spans
}

#[cfg(test)]
mod tests {
    use super::{AddressKind, address_spans, address_with_notes, own_address_spans, whole_address};

    /// `(joined text, emphasized pieces)` of an own-address line.
    fn own(address: &str, kind: AddressKind, short: bool) -> (String, Vec<String>) {
        let spans = own_address_spans(address, kind, short);
        (
            spans.iter().map(|(text, _)| text.as_str()).collect(),
            spans
                .into_iter()
                .filter(|(_, strong)| *strong)
                .map(|(text, _)| text)
                .collect(),
        )
    }

    #[test]
    fn own_evm_address_emphasizes_four_after_0x_and_the_last_four() {
        let address = "0xF9900bb6FF2D2C67858c3468d21c5f103C4Ff646";
        let (joined, strong) = own(address, AddressKind::Evm, false);
        assert_eq!(joined, address, "no spaces, case kept");
        assert_eq!(strong, ["F990", "f646"]);
        let (short, strong) = own(
            "0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73",
            AddressKind::Evm,
            true,
        );
        assert_eq!(short, "0x0Bd7…AD73");
        assert_eq!(strong, ["0Bd7", "AD73"]);
    }

    #[test]
    fn own_solana_address_emphasizes_its_first_and_last_four() {
        let address = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
        let (joined, strong) = own(address, AddressKind::Solana, false);
        assert_eq!(joined, address);
        assert_eq!(strong, ["HAgk", "Kpqk"]);
    }

    #[test]
    fn own_bitcoin_address_skips_the_bech32_prefix_only() {
        for (address, first) in [
            ("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "cr8t"),
            (
                "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
                "5d7r",
            ),
            ("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "w508"),
        ] {
            let (joined, strong) = own(address, AddressKind::Bitcoin, false);
            assert_eq!(joined, address);
            assert_eq!(strong.first().map(String::as_str), Some(first), "{address}");
            assert_eq!(strong.get(1).map(String::len), Some(4));
        }
        // Base58 (legacy, nested segwit): no prefix.
        let (_, strong) = own(
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            AddressKind::Bitcoin,
            false,
        );
        assert_eq!(strong, ["1BvB", "NVN2"]);
        let (_, strong) = own(
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
            AddressKind::Bitcoin,
            false,
        );
        assert_eq!(strong, ["3J98", "WNLy"]);
    }

    #[test]
    fn own_zcash_address_skips_the_two_character_prefix() {
        let (joined, strong) = own(
            "t1Rv4exT7bqhZqi2j7xz8bUHDMxwosrjADU",
            AddressKind::Zcash,
            false,
        );
        assert_eq!(joined, "t1Rv4exT7bqhZqi2j7xz8bUHDMxwosrjADU");
        assert_eq!(strong, ["Rv4e", "jADU"]);
        let (_, strong) = own(
            "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd",
            AddressKind::Zcash,
            false,
        );
        assert_eq!(strong, ["Vz22", "9ojd"]);
        // Too short to have a middle: one plain span.
        assert_eq!(
            own_address_spans("t1abc", AddressKind::Zcash, false),
            [("t1abc".to_owned(), false)]
        );
    }

    #[test]
    fn address_lines_are_drawn_whole_with_their_ends_emphasized() {
        let strong = |text: &str| -> Option<(String, Vec<String>)> {
            address_spans(text).map(|spans| {
                (
                    spans.iter().map(|(piece, _)| piece.as_str()).collect(),
                    spans
                        .into_iter()
                        .filter(|(_, strong)| *strong)
                        .map(|(piece, _)| piece)
                        .collect(),
                )
            })
        };
        let evm = "0xF9900bb6FF2D2C67858c3468d21c5f103C4Ff646";
        for text in [evm, "0xF990 0bb6 FF2D 2C67 858c 3468 d21c 5f10 3C4F f646"] {
            assert_eq!(
                strong(text),
                Some((evm.to_owned(), vec!["F990".to_owned(), "f646".to_owned()])),
                "{text}"
            );
        }
        let sol = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
        for text in [
            sol,
            "HAgk 14Jp MQLg t6rV gv7c BQFJ WFto 5Dqx i472 uT3D Kpqk",
        ] {
            assert_eq!(
                whole_address(text),
                Some((sol.to_owned(), AddressKind::Solana))
            );
        }
        for (text, kind) in [
            (
                "tb1q w508 d6qe jxtd g4y5 r3za rvar y0c5 xw7k xpjz sx",
                AddressKind::Bitcoin,
            ),
            ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", AddressKind::Bitcoin),
            (
                "t1Kg n7v5 a2rK kxC2 4LoX NyHR n4q4 Gs3K EEF",
                AddressKind::Zcash,
            ),
        ] {
            assert_eq!(
                whole_address(text).map(|(_, kind)| kind),
                Some(kind),
                "{text}"
            );
        }
        // Other groupings, altered addresses and other text keep their look.
        for text in [
            "HAgk 14Jp MQLg t6rV gv7c BQFJ WFto 5Dqx i472 uT3D Kpq0",
            "HAg k14J pMQL gt6r Vgv7 cBQF JWFt o5Dq xi47 2uT3 DKpq k",
            "HAgk  14Jp MQLg t6rV gv7c BQFJ WFto 5Dqx i472 uT3D Kpqk",
            "0x F990 0bb6 FF2D 2C67 858c 3468 d21c 5f10 3C4F f646",
            "0xF9900bb6FF2D2C67858c3468d21c5f103C4Ff64",
            "0x98 58Ef FD23",
            "새 계정(아직 없음)",
            "m/44'/60'/0'/0/0",
            "",
        ] {
            assert!(address_spans(text).is_none(), "{text}");
        }
        // An address with its notes (2026-11-14): the address part and the notes.
        let grouped = "0xF990 0bb6 FF2D 2C67 858c 3468 d21c 5f10 3C4F f646";
        assert_eq!(
            address_with_notes(&format!("{grouped} [일반 계정(EOA)] [주소록: A]")),
            Some((grouped, "[일반 계정(EOA)] [주소록: A]"))
        );
        assert_eq!(
            address_with_notes(&format!("{evm} [컨트랙트]")),
            Some((evm, "[컨트랙트]"))
        );
        for text in [
            grouped,
            "0xF990 0bb6 FF2D [일반 계정(EOA)]",
            "새 계정 [일반 계정(EOA)]",
            "",
        ] {
            assert!(address_with_notes(text).is_none(), "{text}");
        }
    }
}
