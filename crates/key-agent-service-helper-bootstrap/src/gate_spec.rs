//! Platform-neutral byte specifications for the helper bootstrap gates.
//!
//! These constants let a debugger parent authenticate the exact x86-64 gate
//! bytes without importing Windows handle types. The public markers are
//! structural sentinels, not secrets, authentication, or authority.

#![forbid(unsafe_code)]

/// Public structural marker loaded into `r10` by the capture gate.
pub const REQUEST_INPUT_MARKER: u64 = 0xA1D7_5E02_9C4B_63F8;

/// Public structural marker loaded into `r11` by the capture gate.
pub const RESPONSE_OUTPUT_MARKER: u64 = 0x6C39_B4E1_27FA_805D;

/// Exact byte length of the injected-channel capture gate.
pub const CAPTURE_GATE_BYTES: usize = 34;

/// Offset of the capture gate's `INT3` instruction from its first byte.
pub const CAPTURE_GATE_BREAKPOINT_OFFSET: usize = 20;

/// Public structural marker loaded into `r10` by the adoption-complete gate.
pub const ADOPTION_COMPLETE_R10_MARKER: u64 = 0xD84F_71A3_C25E_906B;

/// Public structural marker loaded into `r11` by the adoption-complete gate.
pub const ADOPTION_COMPLETE_R11_MARKER: u64 = 0x2B96_E04D_7A13_F5C8;

/// Exact byte length of the adoption-complete gate.
pub const ADOPTION_COMPLETE_GATE_BYTES: usize = 28;

/// Offset of the adoption-complete gate's `INT3` instruction from its first byte.
pub const ADOPTION_COMPLETE_GATE_BREAKPOINT_OFFSET: usize = 20;

/// Builds the exact injected-channel capture gate byte sequence.
///
/// The sequence is `movabs r10, imm64; movabs r11, imm64; int3`, followed by
/// stores through `rcx` and `rdx`, zeroing of both transport registers, and
/// `ret`. Both immediates use the x86-64 little-endian representation.
#[must_use]
pub const fn capture_gate_bytes() -> [u8; CAPTURE_GATE_BYTES] {
    capture_gate_bytes_for_markers(REQUEST_INPUT_MARKER, RESPONSE_OUTPUT_MARKER)
}

/// Builds the exact adoption-complete gate byte sequence.
///
/// The sequence is `movabs r10, imm64; movabs r11, imm64; int3`, followed by
/// zeroing of both marker registers and `ret`. Both immediates use the x86-64
/// little-endian representation.
#[must_use]
pub const fn adoption_complete_gate_bytes() -> [u8; ADOPTION_COMPLETE_GATE_BYTES] {
    adoption_complete_gate_bytes_for_markers(
        ADOPTION_COMPLETE_R10_MARKER,
        ADOPTION_COMPLETE_R11_MARKER,
    )
}

const fn capture_gate_bytes_for_markers(
    r10_marker: u64,
    r11_marker: u64,
) -> [u8; CAPTURE_GATE_BYTES] {
    let mut bytes = [0_u8; CAPTURE_GATE_BYTES];
    bytes[0] = 0x49;
    bytes[1] = 0xBA;
    write_marker(&mut bytes, 2, r10_marker);
    bytes[10] = 0x49;
    bytes[11] = 0xBB;
    write_marker(&mut bytes, 12, r11_marker);
    bytes[20] = 0xCC;
    bytes[21] = 0x4C;
    bytes[22] = 0x89;
    bytes[23] = 0x11;
    bytes[24] = 0x4C;
    bytes[25] = 0x89;
    bytes[26] = 0x1A;
    bytes[27] = 0x45;
    bytes[28] = 0x31;
    bytes[29] = 0xD2;
    bytes[30] = 0x45;
    bytes[31] = 0x31;
    bytes[32] = 0xDB;
    bytes[33] = 0xC3;
    bytes
}

const fn adoption_complete_gate_bytes_for_markers(
    r10_marker: u64,
    r11_marker: u64,
) -> [u8; ADOPTION_COMPLETE_GATE_BYTES] {
    let mut bytes = [0_u8; ADOPTION_COMPLETE_GATE_BYTES];
    bytes[0] = 0x49;
    bytes[1] = 0xBA;
    write_marker(&mut bytes, 2, r10_marker);
    bytes[10] = 0x49;
    bytes[11] = 0xBB;
    write_marker(&mut bytes, 12, r11_marker);
    bytes[20] = 0xCC;
    bytes[21] = 0x45;
    bytes[22] = 0x31;
    bytes[23] = 0xD2;
    bytes[24] = 0x45;
    bytes[25] = 0x31;
    bytes[26] = 0xDB;
    bytes[27] = 0xC3;
    bytes
}

const fn write_marker<const N: usize>(bytes: &mut [u8; N], offset: usize, marker: u64) {
    let marker = marker.to_le_bytes();
    let mut index = 0;
    while index < marker.len() {
        bytes[offset + index] = marker[index];
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ADOPTION_COMPLETE_GATE_BREAKPOINT_OFFSET, ADOPTION_COMPLETE_GATE_BYTES,
        ADOPTION_COMPLETE_R10_MARKER, ADOPTION_COMPLETE_R11_MARKER, CAPTURE_GATE_BREAKPOINT_OFFSET,
        CAPTURE_GATE_BYTES, REQUEST_INPUT_MARKER, RESPONSE_OUTPUT_MARKER,
        adoption_complete_gate_bytes, adoption_complete_gate_bytes_for_markers, capture_gate_bytes,
        capture_gate_bytes_for_markers,
    };

    const CAPTURE_GATE_GOLDEN: [u8; CAPTURE_GATE_BYTES] = [
        0x49, 0xBA, 0xF8, 0x63, 0x4B, 0x9C, 0x02, 0x5E, 0xD7, 0xA1, 0x49, 0xBB, 0x5D, 0x80, 0xFA,
        0x27, 0xE1, 0xB4, 0x39, 0x6C, 0xCC, 0x4C, 0x89, 0x11, 0x4C, 0x89, 0x1A, 0x45, 0x31, 0xD2,
        0x45, 0x31, 0xDB, 0xC3,
    ];

    const ADOPTION_COMPLETE_GATE_GOLDEN: [u8; ADOPTION_COMPLETE_GATE_BYTES] = [
        0x49, 0xBA, 0x6B, 0x90, 0x5E, 0xC2, 0xA3, 0x71, 0x4F, 0xD8, 0x49, 0xBB, 0xC8, 0xF5, 0x13,
        0x7A, 0x4D, 0xE0, 0x96, 0x2B, 0xCC, 0x45, 0x31, 0xD2, 0x45, 0x31, 0xDB, 0xC3,
    ];

    #[test]
    fn public_markers_remain_exact() {
        assert_eq!(REQUEST_INPUT_MARKER, 0xA1D7_5E02_9C4B_63F8);
        assert_eq!(RESPONSE_OUTPUT_MARKER, 0x6C39_B4E1_27FA_805D);
        assert_eq!(ADOPTION_COMPLETE_R10_MARKER, 0xD84F_71A3_C25E_906B);
        assert_eq!(ADOPTION_COMPLETE_R11_MARKER, 0x2B96_E04D_7A13_F5C8);
    }

    #[test]
    fn builders_match_the_complete_golden_sequences() {
        assert_eq!(capture_gate_bytes(), CAPTURE_GATE_GOLDEN);
        assert_eq!(
            adoption_complete_gate_bytes(),
            ADOPTION_COMPLETE_GATE_GOLDEN
        );
    }

    #[test]
    fn breakpoint_offsets_and_sequence_ends_are_exact() {
        assert_eq!(CAPTURE_GATE_BYTES, 34);
        assert_eq!(CAPTURE_GATE_BREAKPOINT_OFFSET, 20);
        assert_eq!(capture_gate_bytes()[CAPTURE_GATE_BREAKPOINT_OFFSET], 0xCC);
        assert_eq!(capture_gate_bytes()[CAPTURE_GATE_BYTES - 1], 0xC3);

        assert_eq!(ADOPTION_COMPLETE_GATE_BYTES, 28);
        assert_eq!(ADOPTION_COMPLETE_GATE_BREAKPOINT_OFFSET, 20);
        assert_eq!(
            adoption_complete_gate_bytes()[ADOPTION_COMPLETE_GATE_BREAKPOINT_OFFSET],
            0xCC
        );
        assert_eq!(
            adoption_complete_gate_bytes()[ADOPTION_COMPLETE_GATE_BYTES - 1],
            0xC3
        );
    }

    #[test]
    fn breakpoint_is_the_only_int3_in_each_sequence() {
        for (bytes, expected_offset) in [
            (
                capture_gate_bytes().as_slice(),
                CAPTURE_GATE_BREAKPOINT_OFFSET,
            ),
            (
                adoption_complete_gate_bytes().as_slice(),
                ADOPTION_COMPLETE_GATE_BREAKPOINT_OFFSET,
            ),
        ] {
            assert_eq!(
                bytes
                    .iter()
                    .enumerate()
                    .filter_map(|(offset, byte)| (*byte == 0xCC).then_some(offset))
                    .collect::<Vec<_>>(),
                [expected_offset]
            );
        }
    }

    #[test]
    fn every_single_bit_sequence_mutation_differs_from_the_golden_sequence() {
        assert_every_single_bit_mutation_differs(capture_gate_bytes());
        assert_every_single_bit_mutation_differs(adoption_complete_gate_bytes());
    }

    #[test]
    fn every_capture_marker_bit_mutation_is_confined_to_its_immediate() {
        assert_every_marker_bit_mutation(
            capture_gate_bytes_for_markers,
            REQUEST_INPUT_MARKER,
            RESPONSE_OUTPUT_MARKER,
        );
    }

    #[test]
    fn every_adoption_marker_bit_mutation_is_confined_to_its_immediate() {
        assert_every_marker_bit_mutation(
            adoption_complete_gate_bytes_for_markers,
            ADOPTION_COMPLETE_R10_MARKER,
            ADOPTION_COMPLETE_R11_MARKER,
        );
    }

    fn assert_every_single_bit_mutation_differs<const N: usize>(golden: [u8; N]) {
        for (byte_index, _) in golden.iter().enumerate() {
            for bit_index in 0..u8::BITS {
                let mut mutated = golden;
                mutated[byte_index] ^= 1_u8 << bit_index;
                assert_ne!(mutated, golden);
            }
        }
    }

    fn assert_every_marker_bit_mutation<const N: usize>(
        builder: fn(u64, u64) -> [u8; N],
        r10_marker: u64,
        r11_marker: u64,
    ) {
        let baseline = builder(r10_marker, r11_marker);
        for marker_byte in 0..size_of::<u64>() {
            for marker_bit in 0..u8::BITS {
                let marker_mask =
                    u64::from(1_u8 << marker_bit) << (marker_byte * u8::BITS as usize);
                assert_one_marker_mutation(
                    baseline,
                    builder(r10_marker ^ marker_mask, r11_marker),
                    2 + marker_byte,
                    marker_bit,
                );
                assert_one_marker_mutation(
                    baseline,
                    builder(r10_marker, r11_marker ^ marker_mask),
                    12 + marker_byte,
                    marker_bit,
                );
            }
        }
    }

    fn assert_one_marker_mutation<const N: usize>(
        baseline: [u8; N],
        mutated: [u8; N],
        changed_index: usize,
        changed_bit: u32,
    ) {
        for (index, (baseline_byte, mutated_byte)) in
            baseline.iter().zip(mutated.iter()).enumerate()
        {
            let expected = if index == changed_index {
                *baseline_byte ^ (1_u8 << changed_bit)
            } else {
                *baseline_byte
            };
            assert_eq!(*mutated_byte, expected);
        }
    }
}
