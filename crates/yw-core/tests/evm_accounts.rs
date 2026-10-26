//! EIP-55 parsing and display (spec/09 §3.4 ACC-6–8, spec/03 §2.1). The eight addresses are
//! the test cases of ERC-55 (github.com/ethereum/ERCs `ERCS/erc-55.md`).

use yw_core::evm::{AddressError, parse_address, to_checksum};

const ERC55: [&str; 8] = [
    "0x52908400098527886E0F7030069857D2E4169EE7",
    "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
    "0xde709f2102306220921060314715629080e2fb77",
    "0x27b1fdb04752bbc536007a920d24acb045561c26",
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
];

#[test]
fn acc_6_accepts_checksummed_all_lower_and_all_upper() {
    for address in ERC55 {
        let digits = address.trim_start_matches("0x");
        let parsed = parse_address(address).unwrap();
        assert_eq!(
            parse_address(&format!("0x{}", digits.to_ascii_lowercase())),
            Ok(parsed),
            "{address}"
        );
        assert_eq!(
            parse_address(&format!("0x{}", digits.to_ascii_uppercase())),
            Ok(parsed),
            "{address}"
        );
    }
}

#[test]
fn acc_7_rejects_bad_checksum_and_format() {
    assert_eq!(
        parse_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"),
        Err(AddressError::BadChecksum)
    );
    for invalid in [
        "0X5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe",
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed0",
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeg",
        "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "",
        "0x",
        " 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    ] {
        assert_eq!(
            parse_address(invalid),
            Err(AddressError::InvalidFormat),
            "{invalid:?}"
        );
    }
    assert!(parse_address("0x0000000000000000000000000000000000000000").is_ok());
}

#[test]
fn acc_8_to_checksum() {
    // The ERC-55 cases are chosen so that the checksum form is exactly the listed text, including
    // the all-caps and all-lowercase groups.
    for address in ERC55 {
        let lower = parse_address(&address.to_ascii_lowercase()).unwrap();
        assert_eq!(to_checksum(&lower), address);
        assert_eq!(lower.to_string(), address);
        assert_eq!(lower.to_lower_hex(), address.to_ascii_lowercase());
    }
    let mixed = parse_address("0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f").unwrap();
    assert_eq!(
        to_checksum(&mixed),
        "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F"
    );
}
