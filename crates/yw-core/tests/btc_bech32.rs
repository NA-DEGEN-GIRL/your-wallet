//! bech32 / bech32m codec (spec/08 §6.2, spec/09 §3.10): the BIP173 string vectors (valid 7,
//! invalid 12) and the BIP350 string vectors (valid 7, invalid 14) through the checksum decoder,
//! the segwit layer on the BIP173/BIP350 address lists, and encoder round trips. Vectors are
//! copied from bitcoin/bips `bip-0173.mediawiki` / `bip-0350.mediawiki` (commit
//! `24e96e870fffaa257b465ce1f0370c14aac588e8`, `tests/vectors/SOURCES.md`).

use yw_core::btc::bech32::{Bech32Error, Variant, decode, decode_segwit, encode, encode_segwit};
use yw_core::hex;

const BIP173_VALID: [&str; 7] = [
    "A12UEL5L",
    "a12uel5l",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
    "?1ezyfcl",
];

const BIP350_VALID: [&str; 7] = [
    "A1LQFN3A",
    "a1lqfn3a",
    "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
    "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
    "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
    "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
    "?1v759aa",
];

/// BIP173 invalid strings with the reason given there and our error.
fn bip173_invalid() -> Vec<(String, Bech32Error)> {
    vec![
        // HRP character out of range (0x20, 0x7F, 0x80).
        (format!("{}1nwldj5", '\u{20}'), Bech32Error::InvalidCharacter),
        (format!("{}1axkwrx", '\u{7f}'), Bech32Error::InvalidCharacter),
        (format!("{}1eym55h", '\u{80}'), Bech32Error::InvalidCharacter),
        // Overall max length exceeded.
        (
            "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx"
                .to_owned(),
            Bech32Error::InvalidLength,
        ),
        ("pzry9x0s0muk".to_owned(), Bech32Error::NoSeparator),
        ("1pzry9x0s0muk".to_owned(), Bech32Error::EmptyHrp),
        // Invalid data character.
        ("x1b4n0q5v".to_owned(), Bech32Error::InvalidCharacter),
        // Too short checksum.
        ("li1dgmt3".to_owned(), Bech32Error::ShortData),
        // Invalid character in checksum (0xFF).
        (format!("de1lg7wt{}", '\u{ff}'), Bech32Error::InvalidCharacter),
        // Checksum calculated with the uppercase form of the HRP.
        ("A1G7SGD8".to_owned(), Bech32Error::Checksum),
        // Empty HRP (7 characters: the length rule fires first).
        ("10a06t8".to_owned(), Bech32Error::InvalidLength),
        ("1qzzfhee".to_owned(), Bech32Error::EmptyHrp),
    ]
}

/// BIP350 invalid strings with the reason given there and our error.
fn bip350_invalid() -> Vec<(String, Bech32Error)> {
    vec![
        (format!("{}1xj0phk", '\u{20}'), Bech32Error::InvalidCharacter),
        (format!("{}1g6xzxy", '\u{7f}'), Bech32Error::InvalidCharacter),
        (format!("{}1vctc34", '\u{80}'), Bech32Error::InvalidCharacter),
        (
            "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4"
                .to_owned(),
            Bech32Error::InvalidLength,
        ),
        ("qyrz8wqd2c9m".to_owned(), Bech32Error::NoSeparator),
        ("1qyrz8wqd2c9m".to_owned(), Bech32Error::EmptyHrp),
        ("y1b0jsk6g".to_owned(), Bech32Error::InvalidCharacter),
        ("lt1igcx5c0".to_owned(), Bech32Error::InvalidCharacter),
        ("in1muywd".to_owned(), Bech32Error::ShortData),
        ("mm1crxm3i".to_owned(), Bech32Error::InvalidCharacter),
        ("au1s5cgom".to_owned(), Bech32Error::InvalidCharacter),
        ("M1VUXWEZ".to_owned(), Bech32Error::Checksum),
        ("16plkw9".to_owned(), Bech32Error::InvalidLength),
        ("1p2gdwpf".to_owned(), Bech32Error::EmptyHrp),
    ]
}

#[test]
fn bip173_strings() {
    assert_eq!(BIP173_VALID.len(), 7);
    for text in BIP173_VALID {
        let decoded = decode(text).unwrap();
        assert_eq!(decoded.variant, Variant::Bech32, "{text}");
        assert_eq!(
            encode(&decoded.hrp, &decoded.data, decoded.variant).unwrap(),
            text.to_ascii_lowercase()
        );
    }
    let invalid = bip173_invalid();
    assert_eq!(invalid.len(), 12);
    for (text, expected) in invalid {
        assert_eq!(decode(&text).err(), Some(expected), "{text:?}");
    }
}

#[test]
fn bip350_strings() {
    assert_eq!(BIP350_VALID.len(), 7);
    for text in BIP350_VALID {
        let decoded = decode(text).unwrap();
        assert_eq!(decoded.variant, Variant::Bech32m, "{text}");
        assert_eq!(
            encode(&decoded.hrp, &decoded.data, decoded.variant).unwrap(),
            text.to_ascii_lowercase()
        );
    }
    let invalid = bip350_invalid();
    assert_eq!(invalid.len(), 14);
    for (text, expected) in invalid {
        assert_eq!(decode(&text).err(), Some(expected), "{text:?}");
    }
}

/// No string is both: each valid vector fails under the other constant (re-encode check).
#[test]
fn variants_are_exclusive() {
    for text in BIP173_VALID {
        let decoded = decode(text).unwrap();
        let other = encode(&decoded.hrp, &decoded.data, Variant::Bech32m).unwrap();
        assert_ne!(other, text.to_ascii_lowercase());
        assert_eq!(decode(&other).unwrap().variant, Variant::Bech32m);
    }
}

/// BIP173/BIP350 address lists through the segwit layer (before any network policy).
#[test]
#[expect(clippy::too_many_lines, reason = "the BIP173/BIP350 address lists")]
fn segwit_layer() {
    let valid = [
        (
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
            "bc",
            0,
            "751e76e8199196d454941c45d1b3a323f1433bd6",
        ),
        (
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            "tb",
            0,
            "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
        ),
        (
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
            "bc",
            1,
            "751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
        ),
        ("BC1SW50QGDZ25J", "bc", 16, "751e"),
        (
            "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
            "bc",
            2,
            "751e76e8199196d454941c45d1b3a323",
        ),
        (
            "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
            "tb",
            0,
            "000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
        ),
        (
            "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
            "tb",
            1,
            "000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
        ),
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            "bc",
            1,
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ),
    ];
    for (text, hrp, version, program) in valid {
        let decoded = decode_segwit(text).unwrap();
        assert_eq!(decoded.hrp, hrp);
        assert_eq!(decoded.version, version);
        assert_eq!(hex::encode(&decoded.program), program);
        assert_eq!(
            encode_segwit(hrp, version, &decoded.program).unwrap(),
            text.to_ascii_lowercase()
        );
    }
    let invalid = [
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
            Bech32Error::WrongChecksumVariant,
        ),
        (
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
            Bech32Error::WrongChecksumVariant,
        ),
        (
            "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
            Bech32Error::InvalidWitnessVersion,
        ),
        ("bc1pw5dgrnzv", Bech32Error::InvalidProgramLength),
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
            Bech32Error::InvalidProgramLength,
        ),
        (
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            Bech32Error::InvalidProgramLength,
        ),
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
            Bech32Error::InvalidPadding,
        ),
        (
            "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
            Bech32Error::InvalidPadding,
        ),
        ("bc1gmk9yu", Bech32Error::InvalidWitnessVersion),
        // BIP173 lists these v1+ addresses as valid; under BIP350 their bech32 checksum is wrong.
        (
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
            Bech32Error::WrongChecksumVariant,
        ),
        ("BC1SW50QA3JX3S", Bech32Error::WrongChecksumVariant),
        (
            "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
            Bech32Error::WrongChecksumVariant,
        ),
        // BIP173 invalid list.
        (
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
            Bech32Error::Checksum,
        ),
        (
            "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
            Bech32Error::InvalidWitnessVersion,
        ),
        ("bc1rw5uspcuh", Bech32Error::InvalidProgramLength),
        (
            "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
            Bech32Error::InvalidProgramLength,
        ),
        (
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
            Bech32Error::MixedCase,
        ),
        (
            "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
            Bech32Error::InvalidPadding,
        ),
        (
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
            Bech32Error::InvalidPadding,
        ),
    ];
    for (text, expected) in invalid {
        assert_eq!(decode_segwit(text).err(), Some(expected), "{text}");
    }
}

#[test]
fn encoder_rejections() {
    assert_eq!(encode("", &[], Variant::Bech32), Err(Bech32Error::EmptyHrp));
    assert_eq!(
        encode("bc", &[32], Variant::Bech32),
        Err(Bech32Error::InvalidCharacter)
    );
    assert_eq!(
        encode("b c", &[0], Variant::Bech32),
        Err(Bech32Error::InvalidCharacter)
    );
    // The shortest string (1-character HRP, no data) is the first BIP173 vector.
    assert_eq!(encode("A", &[], Variant::Bech32).as_deref(), Ok("a12uel5l"));
    assert_eq!(
        encode("bc", &[0; 83], Variant::Bech32),
        Err(Bech32Error::InvalidLength)
    );
    assert_eq!(
        encode_segwit("bc", 17, &[0; 20]),
        Err(Bech32Error::InvalidWitnessVersion)
    );
    assert_eq!(
        encode_segwit("bc", 0, &[0; 21]),
        Err(Bech32Error::InvalidProgramLength)
    );
    assert_eq!(
        encode_segwit("bc", 1, &[0; 41]),
        Err(Bech32Error::InvalidProgramLength)
    );
    assert_eq!(
        encode_segwit("bc", 1, &[0; 1]),
        Err(Bech32Error::InvalidProgramLength)
    );
    assert_eq!(
        encode_segwit("BC", 0, &[0; 20]).unwrap(),
        encode_segwit("bc", 0, &[0; 20]).unwrap()
    );
}
