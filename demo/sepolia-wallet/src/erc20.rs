//! Strict, pure ERC-20 helpers for the standalone Sepolia demo.
//!
//! This module performs no network, storage, signing, or UI work. Callers must
//! still verify the pinned Sepolia chain before obtaining the byte strings that
//! are decoded here.

use core::fmt;

const ABI_WORD_BYTES: usize = 32;
const ADDRESS_BYTES: usize = 20;
const MAX_SYMBOL_BYTES: usize = 16;
const MAX_TOKEN_DECIMALS: u8 = 36;
const MAX_AMOUNT_INPUT_BYTES: usize = 128;
const MIN_TOKEN_GAS_ESTIMATE: u64 = 21_000;
const MAX_TOKEN_GAS_ESTIMATE: u64 = 416_666;
const MAX_TOKEN_GAS_LIMIT: u64 = 500_000;

pub(crate) const DECIMALS_SELECTOR: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67];
pub(crate) const SYMBOL_SELECTOR: [u8; 4] = [0x95, 0xd8, 0x9b, 0x41];
pub(crate) const BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
pub(crate) const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Erc20Error {
    InvalidAbi,
    InvalidSymbol,
    InvalidDecimals,
    InvalidAmount,
    InvalidGasEstimate,
    TokenRejectedTransfer,
}

impl fmt::Debug for Erc20Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidAbi => "Erc20Error::InvalidAbi",
            Self::InvalidSymbol => "Erc20Error::InvalidSymbol",
            Self::InvalidDecimals => "Erc20Error::InvalidDecimals",
            Self::InvalidAmount => "Erc20Error::InvalidAmount",
            Self::InvalidGasEstimate => "Erc20Error::InvalidGasEstimate",
            Self::TokenRejectedTransfer => "Erc20Error::TokenRejectedTransfer",
        })
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct TokenAmount([u8; ABI_WORD_BYTES]);

impl fmt::Debug for TokenAmount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenAmount([REDACTED])")
    }
}

impl TokenAmount {
    const ZERO: Self = Self([0; ABI_WORD_BYTES]);

    pub(crate) const fn from_be_bytes(bytes: [u8; ABI_WORD_BYTES]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_be_bytes(&self) -> &[u8; ABI_WORD_BYTES] {
        &self.0
    }

    pub(crate) fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    fn checked_mul_small(self, multiplier: u8) -> Option<Self> {
        let mut output = [0_u8; ABI_WORD_BYTES];
        let mut carry = 0_u16;
        for index in (0..ABI_WORD_BYTES).rev() {
            let product = u16::from(self.0[index]) * u16::from(multiplier) + carry;
            output[index] = (product & 0xff) as u8;
            carry = product >> 8;
        }
        (carry == 0).then_some(Self(output))
    }

    fn checked_add_small(self, value: u8) -> Option<Self> {
        let mut output = self.0;
        let mut carry = u16::from(value);
        for byte in output.iter_mut().rev() {
            let sum = u16::from(*byte) + carry;
            *byte = (sum & 0xff) as u8;
            carry = sum >> 8;
            if carry == 0 {
                break;
            }
        }
        (carry == 0).then_some(Self(output))
    }

    fn div_mod_small(&mut self, divisor: u8) -> u8 {
        let mut remainder = 0_u16;
        for byte in &mut self.0 {
            let value = (remainder << 8) | u16::from(*byte);
            *byte = (value / u16::from(divisor)) as u8;
            remainder = value % u16::from(divisor);
        }
        remainder as u8
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct TokenSymbol(String);

impl fmt::Debug for TokenSymbol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenSymbol([REDACTED])")
    }
}

impl TokenSymbol {
    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

pub(crate) const fn decimals_call_data() -> [u8; 4] {
    DECIMALS_SELECTOR
}

pub(crate) const fn symbol_call_data() -> [u8; 4] {
    SYMBOL_SELECTOR
}

pub(crate) fn balance_of_call_data(owner: [u8; ADDRESS_BYTES]) -> [u8; 36] {
    let mut output = [0_u8; 36];
    output[..4].copy_from_slice(&BALANCE_OF_SELECTOR);
    output[16..36].copy_from_slice(&owner);
    output
}

pub(crate) fn transfer_call_data(recipient: [u8; ADDRESS_BYTES], amount: TokenAmount) -> [u8; 68] {
    let mut output = [0_u8; 68];
    output[..4].copy_from_slice(&TRANSFER_SELECTOR);
    output[16..36].copy_from_slice(&recipient);
    output[36..].copy_from_slice(amount.as_be_bytes());
    output
}

pub(crate) fn decode_decimals(output: &[u8]) -> Result<u8, Erc20Error> {
    let word: &[u8; ABI_WORD_BYTES] = output.try_into().map_err(|_| Erc20Error::InvalidDecimals)?;
    if word[..ABI_WORD_BYTES - 1].iter().any(|byte| *byte != 0)
        || word[ABI_WORD_BYTES - 1] > MAX_TOKEN_DECIMALS
    {
        return Err(Erc20Error::InvalidDecimals);
    }
    Ok(word[ABI_WORD_BYTES - 1])
}

pub(crate) fn decode_symbol(output: &[u8]) -> Result<Option<TokenSymbol>, Erc20Error> {
    if output.is_empty() {
        return Ok(None);
    }
    if output.len() == ABI_WORD_BYTES {
        let end = output
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(output.len());
        if output[end..].iter().any(|byte| *byte != 0) {
            return Err(Erc20Error::InvalidAbi);
        }
        return validated_symbol(&output[..end]);
    }
    if output.len() < ABI_WORD_BYTES * 2 || !output.len().is_multiple_of(ABI_WORD_BYTES) {
        return Err(Erc20Error::InvalidAbi);
    }
    let offset = canonical_small_word(&output[..ABI_WORD_BYTES])?;
    if offset != ABI_WORD_BYTES {
        return Err(Erc20Error::InvalidAbi);
    }
    let length = canonical_small_word(&output[ABI_WORD_BYTES..ABI_WORD_BYTES * 2])?;
    if length > MAX_SYMBOL_BYTES {
        return Err(Erc20Error::InvalidSymbol);
    }
    let padded_length = length
        .checked_add(ABI_WORD_BYTES - 1)
        .and_then(|value| value.checked_div(ABI_WORD_BYTES))
        .and_then(|words| words.checked_mul(ABI_WORD_BYTES))
        .ok_or(Erc20Error::InvalidAbi)?;
    let expected_length = ABI_WORD_BYTES
        .checked_mul(2)
        .and_then(|prefix| prefix.checked_add(padded_length))
        .ok_or(Erc20Error::InvalidAbi)?;
    if output.len() != expected_length {
        return Err(Erc20Error::InvalidAbi);
    }
    let value_end = ABI_WORD_BYTES
        .checked_mul(2)
        .and_then(|prefix| prefix.checked_add(length))
        .ok_or(Erc20Error::InvalidAbi)?;
    if output[value_end..].iter().any(|byte| *byte != 0) {
        return Err(Erc20Error::InvalidAbi);
    }
    validated_symbol(&output[ABI_WORD_BYTES * 2..value_end])
}

pub(crate) fn decode_balance(output: &[u8]) -> Result<TokenAmount, Erc20Error> {
    let bytes: [u8; ABI_WORD_BYTES] = output.try_into().map_err(|_| Erc20Error::InvalidAbi)?;
    Ok(TokenAmount::from_be_bytes(bytes))
}

pub(crate) fn validate_transfer_result(output: &[u8]) -> Result<(), Erc20Error> {
    if output.is_empty() {
        return Ok(());
    }
    let word: &[u8; ABI_WORD_BYTES] = output
        .try_into()
        .map_err(|_| Erc20Error::TokenRejectedTransfer)?;
    if word[..ABI_WORD_BYTES - 1].iter().all(|byte| *byte == 0) && word[ABI_WORD_BYTES - 1] == 1 {
        Ok(())
    } else {
        Err(Erc20Error::TokenRejectedTransfer)
    }
}

pub(crate) fn parse_token_amount(input: &str, decimals: u8) -> Result<TokenAmount, Erc20Error> {
    if decimals > MAX_TOKEN_DECIMALS
        || input.is_empty()
        || input.len() > MAX_AMOUNT_INPUT_BYTES
        || input.trim() != input
        || input
            .bytes()
            .any(|byte| matches!(byte, b'+' | b'-' | b'e' | b'E' | b','))
    {
        return Err(Erc20Error::InvalidAmount);
    }
    let mut parts = input.split('.');
    let integer = parts.next().ok_or(Erc20Error::InvalidAmount)?;
    let fraction = parts.next();
    if parts.next().is_some()
        || integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Erc20Error::InvalidAmount);
    }
    let fraction = fraction.unwrap_or("");
    if fraction.len() > usize::from(decimals)
        || fraction.bytes().any(|byte| !byte.is_ascii_digit())
        || input.ends_with('.')
    {
        return Err(Erc20Error::InvalidAmount);
    }

    let mut output = TokenAmount::ZERO;
    for digit in integer.bytes().chain(fraction.bytes()) {
        output = output
            .checked_mul_small(10)
            .and_then(|word| word.checked_add_small(digit - b'0'))
            .ok_or(Erc20Error::InvalidAmount)?;
    }
    for _ in fraction.len()..usize::from(decimals) {
        output = output
            .checked_mul_small(10)
            .ok_or(Erc20Error::InvalidAmount)?;
    }
    if output.is_zero() {
        return Err(Erc20Error::InvalidAmount);
    }
    Ok(output)
}

pub(crate) fn format_token_amount(amount: TokenAmount, decimals: u8) -> Result<String, Erc20Error> {
    if decimals > MAX_TOKEN_DECIMALS {
        return Err(Erc20Error::InvalidDecimals);
    }
    let mut decimal = decimal_string(amount);
    let decimals = usize::from(decimals);
    if decimals == 0 {
        return Ok(decimal);
    }
    if decimal.len() <= decimals {
        decimal.insert_str(0, &"0".repeat(decimals + 1 - decimal.len()));
    }
    let split = decimal.len() - decimals;
    let mut fraction = decimal.split_off(split);
    while fraction.ends_with('0') {
        fraction.pop();
    }
    if fraction.is_empty() {
        Ok(decimal)
    } else {
        Ok(format!("{decimal}.{fraction}"))
    }
}

pub(crate) fn token_gas_limit(estimated_gas: u64) -> Result<u64, Erc20Error> {
    if !(MIN_TOKEN_GAS_ESTIMATE..=MAX_TOKEN_GAS_ESTIMATE).contains(&estimated_gas) {
        return Err(Erc20Error::InvalidGasEstimate);
    }
    let scaled = estimated_gas
        .checked_mul(120)
        .and_then(|value| value.checked_add(99))
        .ok_or(Erc20Error::InvalidGasEstimate)?;
    let limit = scaled / 100;
    if limit > MAX_TOKEN_GAS_LIMIT {
        return Err(Erc20Error::InvalidGasEstimate);
    }
    Ok(limit)
}

fn canonical_small_word(word: &[u8]) -> Result<usize, Erc20Error> {
    let word: &[u8; ABI_WORD_BYTES] = word.try_into().map_err(|_| Erc20Error::InvalidAbi)?;
    if word[..ABI_WORD_BYTES - 1].iter().any(|byte| *byte != 0) {
        return Err(Erc20Error::InvalidAbi);
    }
    Ok(usize::from(word[ABI_WORD_BYTES - 1]))
}

fn validated_symbol(bytes: &[u8]) -> Result<Option<TokenSymbol>, Erc20Error> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > MAX_SYMBOL_BYTES || !bytes.iter().copied().all(is_safe_symbol_byte) {
        return Err(Erc20Error::InvalidSymbol);
    }
    let value = String::from_utf8(bytes.to_vec()).map_err(|_| Erc20Error::InvalidSymbol)?;
    Ok(Some(TokenSymbol(value)))
}

const fn is_safe_symbol_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'$' | b'+' | b'-' | b'.' | b'_')
}

fn decimal_string(mut amount: TokenAmount) -> String {
    if amount.is_zero() {
        return "0".to_owned();
    }
    let mut reverse = Vec::new();
    while !amount.is_zero() {
        reverse.push(b'0' + amount.div_mod_small(10));
    }
    reverse.reverse();
    String::from_utf8(reverse).unwrap_or_else(|_| "0".to_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        BALANCE_OF_SELECTOR, DECIMALS_SELECTOR, Erc20Error, SYMBOL_SELECTOR, TRANSFER_SELECTOR,
        TokenAmount, balance_of_call_data, decimals_call_data, decode_balance, decode_decimals,
        decode_symbol, format_token_amount, parse_token_amount, symbol_call_data, token_gas_limit,
        transfer_call_data, validate_transfer_result,
    };

    fn dynamic_symbol(value: &[u8]) -> Vec<u8> {
        let padded = value.len().div_ceil(32) * 32;
        let mut output = vec![0_u8; 64 + padded];
        output[31] = 32;
        output[63] = u8::try_from(value.len()).unwrap_or(u8::MAX);
        output[64..64 + value.len()].copy_from_slice(value);
        output
    }

    #[test]
    fn selectors_and_calldata_are_exact() {
        assert_eq!(decimals_call_data(), DECIMALS_SELECTOR);
        assert_eq!(symbol_call_data(), SYMBOL_SELECTOR);

        let owner = [0x11; 20];
        let balance = balance_of_call_data(owner);
        assert_eq!(&balance[..4], &BALANCE_OF_SELECTOR);
        assert_eq!(&balance[4..16], &[0; 12]);
        assert_eq!(&balance[16..], &owner);

        let recipient = [0x22; 20];
        let mut amount_bytes = [0_u8; 32];
        amount_bytes[30..].copy_from_slice(&0x1234_u16.to_be_bytes());
        let transfer = transfer_call_data(recipient, TokenAmount::from_be_bytes(amount_bytes));
        assert_eq!(&transfer[..4], &TRANSFER_SELECTOR);
        assert_eq!(&transfer[4..16], &[0; 12]);
        assert_eq!(&transfer[16..36], &recipient);
        assert_eq!(&transfer[36..], &amount_bytes);
    }

    #[test]
    fn decimals_and_balance_require_exact_words() {
        for decimals in [0_u8, 18, 36] {
            let mut word = [0_u8; 32];
            word[31] = decimals;
            assert_eq!(decode_decimals(&word), Ok(decimals));
        }
        let mut too_large = [0_u8; 32];
        too_large[31] = 37;
        assert_eq!(
            decode_decimals(&too_large),
            Err(Erc20Error::InvalidDecimals)
        );
        let mut noncanonical = [0_u8; 32];
        noncanonical[0] = 1;
        assert_eq!(
            decode_decimals(&noncanonical),
            Err(Erc20Error::InvalidDecimals)
        );
        for length in [0_usize, 31, 33] {
            assert_eq!(
                decode_decimals(&vec![0; length]),
                Err(Erc20Error::InvalidDecimals)
            );
            assert_eq!(
                decode_balance(&vec![0; length]),
                Err(Erc20Error::InvalidAbi)
            );
        }
        let balance = [0x55; 32];
        assert_eq!(
            decode_balance(&balance).map(|value| *value.as_be_bytes()),
            Ok(balance)
        );
    }

    #[test]
    fn symbol_accepts_only_canonical_bounded_safe_ascii() {
        let dynamic = dynamic_symbol(b"TOK-1");
        assert_eq!(
            decode_symbol(&dynamic)
                .and_then(|symbol| symbol.ok_or(Erc20Error::InvalidSymbol))
                .map(|symbol| symbol.as_str().to_owned()),
            Ok("TOK-1".to_owned())
        );

        let mut legacy = [0_u8; 32];
        legacy[..4].copy_from_slice(b"USDC");
        assert_eq!(
            decode_symbol(&legacy)
                .and_then(|symbol| symbol.ok_or(Erc20Error::InvalidSymbol))
                .map(|symbol| symbol.as_str().to_owned()),
            Ok("USDC".to_owned())
        );
        assert_eq!(decode_symbol(&[]), Ok(None));

        for invalid in [
            b"has space".as_slice(),
            b"line\nfeed".as_slice(),
            &[0xff],
            b"0123456789abcdefg".as_slice(),
        ] {
            assert_eq!(
                decode_symbol(&dynamic_symbol(invalid)),
                Err(Erc20Error::InvalidSymbol)
            );
        }
    }

    #[test]
    fn symbol_rejects_malformed_offsets_lengths_padding_and_trailing_data() {
        let valid = dynamic_symbol(b"TOKEN");
        for length in 1..valid.len() {
            assert!(decode_symbol(&valid[..length]).is_err());
        }

        let mut wrong_offset = valid.clone();
        wrong_offset[31] = 64;
        assert_eq!(decode_symbol(&wrong_offset), Err(Erc20Error::InvalidAbi));

        let mut high_offset = valid.clone();
        high_offset[0] = 1;
        assert_eq!(decode_symbol(&high_offset), Err(Erc20Error::InvalidAbi));

        let mut wrong_length = valid.clone();
        wrong_length[63] = 17;
        assert_eq!(decode_symbol(&wrong_length), Err(Erc20Error::InvalidSymbol));

        let mut bad_padding = valid.clone();
        bad_padding[95] = 1;
        assert_eq!(decode_symbol(&bad_padding), Err(Erc20Error::InvalidAbi));

        let mut trailing = valid;
        trailing.extend_from_slice(&[0; 32]);
        assert_eq!(decode_symbol(&trailing), Err(Erc20Error::InvalidAbi));

        let mut legacy_bad_padding = [0_u8; 32];
        legacy_bad_padding[..4].copy_from_slice(b"TOK\0");
        legacy_bad_padding[8] = 1;
        assert_eq!(
            decode_symbol(&legacy_bad_padding),
            Err(Erc20Error::InvalidAbi)
        );
    }

    #[test]
    fn transfer_result_accepts_empty_or_canonical_true_only() {
        assert_eq!(validate_transfer_result(&[]), Ok(()));
        let mut true_word = [0_u8; 32];
        true_word[31] = 1;
        assert_eq!(validate_transfer_result(&true_word), Ok(()));

        let false_word = [0_u8; 32];
        assert_eq!(
            validate_transfer_result(&false_word),
            Err(Erc20Error::TokenRejectedTransfer)
        );
        let mut noncanonical = true_word;
        noncanonical[0] = 1;
        assert_eq!(
            validate_transfer_result(&noncanonical),
            Err(Erc20Error::TokenRejectedTransfer)
        );
        for length in [1_usize, 31, 33] {
            assert_eq!(
                validate_transfer_result(&vec![0; length]),
                Err(Erc20Error::TokenRejectedTransfer)
            );
        }
    }

    #[test]
    fn token_amount_parser_and_formatter_are_exact_without_floats() {
        let amount = parse_token_amount("001.2500", 18).expect("parse token amount");
        assert_eq!(format_token_amount(amount, 18), Ok("1.25".to_owned()));
        assert_eq!(
            parse_token_amount("0001", 0).and_then(|value| format_token_amount(value, 0)),
            Ok("1".to_owned())
        );
        assert_eq!(
            parse_token_amount("0.000000000000000001", 18).map(|value| value.as_be_bytes()[31]),
            Ok(1)
        );

        for invalid in [
            "", "0", "0.0", ".1", "1.", "+1", "-1", "1e2", "1,2", " 1", "1 ",
        ] {
            assert_eq!(
                parse_token_amount(invalid, 18),
                Err(Erc20Error::InvalidAmount)
            );
        }
        assert_eq!(
            parse_token_amount("1.0000000000000000001", 18),
            Err(Erc20Error::InvalidAmount)
        );
        assert_eq!(parse_token_amount("1", 37), Err(Erc20Error::InvalidAmount));

        let maximum =
            "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        let overflow =
            "115792089237316195423570985008687907853269984665640564039457584007913129639936";
        let maximum_amount = parse_token_amount(maximum, 0).expect("parse uint256 maximum");
        assert_eq!(
            format_token_amount(maximum_amount, 0),
            Ok(maximum.to_owned())
        );
        assert_eq!(
            parse_token_amount(overflow, 0),
            Err(Erc20Error::InvalidAmount)
        );
    }

    #[test]
    fn gas_margin_is_ceil_bounded_and_never_exceeds_half_million() {
        assert_eq!(token_gas_limit(21_000), Ok(25_200));
        assert_eq!(token_gas_limit(21_001), Ok(25_202));
        assert_eq!(token_gas_limit(416_666), Ok(500_000));
        assert_eq!(token_gas_limit(20_999), Err(Erc20Error::InvalidGasEstimate));
        assert_eq!(
            token_gas_limit(416_667),
            Err(Erc20Error::InvalidGasEstimate)
        );
        assert_eq!(
            token_gas_limit(u64::MAX),
            Err(Erc20Error::InvalidGasEstimate)
        );
    }

    #[test]
    fn debug_output_is_payload_free() {
        let amount = TokenAmount::from_be_bytes([0x41; 32]);
        assert_eq!(format!("{amount:?}"), "TokenAmount([REDACTED])");
        let symbol = decode_symbol(&dynamic_symbol(b"PRIVATE"))
            .expect("decode symbol")
            .expect("symbol present");
        assert_eq!(format!("{symbol:?}"), "TokenSymbol([REDACTED])");
        assert_eq!(
            format!("{:?}", Erc20Error::InvalidAbi),
            "Erc20Error::InvalidAbi"
        );
    }
}
