//! Minimal BER-TLV (ISO 7816-4 / OpenPGP card §4.4.1 / NIST SP 800-73-4 §3) for the card
//! applets: tags of 1–2 bytes (first byte `xF`/`x1F` continuation), definite lengths up to
//! 65,535 (`81 xx`, `82 xx xx`). Parsing is strict: indefinite lengths, lengths beyond the
//! buffer and trailing bytes are errors.
#![deny(clippy::indexing_slicing)]

use super::CardError;

/// Appends the BER length of `len`.
///
/// # Errors
///
/// [`CardError::TooLarge`] above 65,535.
pub fn push_len(out: &mut Vec<u8>, len: usize) -> Result<(), CardError> {
    if len < 0x80 {
        out.push(u8::try_from(len).map_err(|_| CardError::TooLarge)?);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(u8::try_from(len).map_err(|_| CardError::TooLarge)?);
    } else {
        let len = u16::try_from(len).map_err(|_| CardError::TooLarge)?;
        out.push(0x82);
        out.extend_from_slice(&len.to_be_bytes());
    }
    Ok(())
}

/// Appends the tag bytes of `tag` (1 byte if `< 0x100`, else 2 big-endian bytes).
pub fn push_tag(out: &mut Vec<u8>, tag: u16) {
    if tag > 0xFF {
        out.extend_from_slice(&tag.to_be_bytes());
    } else {
        out.push(tag.to_be_bytes()[1]);
    }
}

/// Appends `tag ‖ len ‖ value`.
///
/// # Errors
///
/// [`CardError::TooLarge`] above 65,535 value bytes.
pub fn push(out: &mut Vec<u8>, tag: u16, value: &[u8]) -> Result<(), CardError> {
    push_tag(out, tag);
    push_len(out, value.len())?;
    out.extend_from_slice(value);
    Ok(())
}

/// `tag ‖ len ‖ value` as a new buffer.
///
/// # Errors
///
/// [`CardError::TooLarge`].
pub fn encode(tag: u16, value: &[u8]) -> Result<Vec<u8>, CardError> {
    let mut out = Vec::with_capacity(value.len().saturating_add(5));
    push(&mut out, tag, value)?;
    Ok(out)
}

/// One parsed element borrowing from the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// Tag (1 or 2 bytes).
    pub tag: u16,
    /// Value.
    pub value: &'a [u8],
}

fn read_tag(bytes: &[u8]) -> Option<(u16, &[u8])> {
    let (first, rest) = bytes.split_first()?;
    if first & 0x1F == 0x1F {
        let (second, rest) = rest.split_first()?;
        if second & 0x80 != 0 {
            return None; // three-byte tags are not used by these applets
        }
        Some((u16::from_be_bytes([*first, *second]), rest))
    } else {
        Some((u16::from(*first), rest))
    }
}

fn read_len(bytes: &[u8]) -> Option<(usize, &[u8])> {
    let (first, rest) = bytes.split_first()?;
    match *first {
        0x00..=0x7F => Some((usize::from(*first), rest)),
        0x81 => {
            let (len, rest) = rest.split_first()?;
            Some((usize::from(*len), rest))
        }
        0x82 => {
            let (len, rest) = rest.split_first_chunk::<2>()?;
            Some((usize::from(u16::from_be_bytes(*len)), rest))
        }
        _ => None,
    }
}

/// Reads one element from the front of `bytes`, returning it and the rest.
///
/// # Errors
///
/// [`CardError::Malformed`].
pub fn next(bytes: &[u8]) -> Result<(Tlv<'_>, &[u8]), CardError> {
    let (tag, rest) = read_tag(bytes).ok_or(CardError::Malformed)?;
    let (len, rest) = read_len(rest).ok_or(CardError::Malformed)?;
    let (value, rest) = rest.split_at_checked(len).ok_or(CardError::Malformed)?;
    Ok((Tlv { tag, value }, rest))
}

/// Parses a whole buffer as a sequence of elements (no trailing bytes).
///
/// # Errors
///
/// [`CardError::Malformed`].
pub fn parse_all(mut bytes: &[u8]) -> Result<Vec<Tlv<'_>>, CardError> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let (element, rest) = next(bytes)?;
        out.push(element);
        bytes = rest;
    }
    Ok(out)
}

/// The value of the first element with `tag` in a sequence.
///
/// # Errors
///
/// [`CardError::Malformed`] for a parse error or a missing tag.
pub fn find(bytes: &[u8], tag: u16) -> Result<&[u8], CardError> {
    parse_all(bytes)?
        .into_iter()
        .find(|element| element.tag == tag)
        .map(|element| element.value)
        .ok_or(CardError::Malformed)
}

/// The value of a buffer that must be exactly one element with `tag`.
///
/// # Errors
///
/// [`CardError::Malformed`].
pub fn unwrap_single(bytes: &[u8], tag: u16) -> Result<&[u8], CardError> {
    let (element, rest) = next(bytes)?;
    if element.tag != tag || !rest.is_empty() {
        return Err(CardError::Malformed);
    }
    Ok(element.value)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, reason = "test assertions on fixed frames")]
mod tests {
    use super::*;

    #[test]
    fn lengths_round_trip() {
        for len in [0_usize, 1, 0x7F, 0x80, 0xFF, 0x100, 1_000] {
            let value = vec![0x5A; len];
            let encoded = encode(0x7F49, &value).unwrap();
            let (element, rest) = next(&encoded).unwrap();
            assert_eq!(element.tag, 0x7F49);
            assert_eq!(element.value.len(), len);
            assert!(rest.is_empty());
        }
        let mut out = Vec::new();
        push_len(&mut out, 0x80).unwrap();
        assert_eq!(out, [0x81, 0x80]);
        out.clear();
        push_len(&mut out, 0x1234).unwrap();
        assert_eq!(out, [0x82, 0x12, 0x34]);
        assert!(push_len(&mut out, 70_000).is_err());
    }

    #[test]
    fn strictness() {
        assert!(next(&[0x86, 0x05, 1, 2]).is_err());
        assert!(next(&[0x86, 0x80]).is_err());
        assert!(next(&[0x86, 0x83, 0, 0, 1]).is_err());
        assert!(next(&[0x5F]).is_err());
        assert!(unwrap_single(&[0x86, 1, 0, 0], 0x86).is_err());
        assert!(unwrap_single(&[0x86, 1, 0], 0x87).is_err());
        assert_eq!(
            find(&[0x01, 1, 0x11, 0x02, 2, 3, 4], 0x02).unwrap(),
            &[3, 4]
        );
        assert!(find(&[0x01, 1, 0x11], 0x02).is_err());
        assert_eq!(read_tag(&[0x5F, 0x48, 0]).unwrap().0, 0x5F48);
    }
}
