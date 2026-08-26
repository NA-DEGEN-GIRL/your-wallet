//! Static two-gate preflight for a service-launched UI helper.
//!
//! This module reopens an already pinned helper only for bounded sequential
//! reading. The reopened handle must name the same file object before and after
//! the read. A pure parser then proves that the exact capture and
//! adoption-complete instruction sequences each occur once in initialized,
//! executable, non-writable code.

#![forbid(unsafe_code)]

use core::fmt;
use core::mem::size_of;
use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsRawHandle as _;

use key_agent_service_helper_bootstrap::{
    ADOPTION_COMPLETE_GATE_BREAKPOINT_OFFSET, CAPTURE_GATE_BREAKPOINT_OFFSET,
    adoption_complete_gate_bytes, capture_gate_bytes,
};
use thiserror::Error;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

use crate::exact_image::{authenticate_mapped_image, held_helper_file_identity};
use crate::helper::VerifiedHelper;

const MAX_SERVICE_HELPER_IMAGE_BYTES: u64 = 256 * 1024 * 1024;

/// Data-free failures from the dormant service helper gate preflight.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum ServiceHelperGatePreflightError {
    /// The held artifact is not one of the two admitted UI helper roles.
    #[error("service helper gate preflight rejected the helper role")]
    Role,
    /// The retained and reopened file object could not be proven stable.
    #[error("service helper gate preflight could not retain exact file identity")]
    Artifact,
    /// The bounded image did not contain the one exact two-gate layout.
    #[error("service helper gate preflight rejected the executable layout")]
    Image,
}

/// Opaque RVAs for the exact two cooperative gates in one admitted image.
///
/// The value is intentionally move-only. It exposes only the addresses that a
/// future debugger verifier must bind to the already authenticated image base.
#[must_use = "the two-gate layout must remain bound to its verified helper"]
pub(super) struct ServiceHelperGateLayout {
    capture_sequence_rva: u32,
    capture_breakpoint_rva: u32,
    adoption_sequence_rva: u32,
    adoption_breakpoint_rva: u32,
    size_of_image: u32,
}

impl ServiceHelperGateLayout {
    pub(super) const fn capture_sequence_rva(&self) -> u32 {
        self.capture_sequence_rva
    }

    pub(super) const fn capture_breakpoint_rva(&self) -> u32 {
        self.capture_breakpoint_rva
    }

    pub(super) const fn adoption_sequence_rva(&self) -> u32 {
        self.adoption_sequence_rva
    }

    pub(super) const fn adoption_breakpoint_rva(&self) -> u32 {
        self.adoption_breakpoint_rva
    }

    pub(super) const fn size_of_image(&self) -> u32 {
        self.size_of_image
    }
}

impl fmt::Debug for ServiceHelperGateLayout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceHelperGateLayout([REDACTED TWO-GATE RVAS])")
    }
}

/// Reopens and statically authenticates the two cooperative gate sequences.
///
/// The caller must keep `artifact` alive through all later image and debugger
/// authentication. This function allocates no launch resource and exposes no
/// path, file identity, bytes, marker, or handle.
pub(super) fn preflight_service_helper_gates(
    artifact: &VerifiedHelper,
) -> Result<ServiceHelperGateLayout, ServiceHelperGatePreflightError> {
    if (!artifact.is_approval_frontend() && !artifact.is_secret_input_frontend())
        || !artifact.path().is_absolute()
    {
        return Err(ServiceHelperGatePreflightError::Role);
    }

    let held_before = held_helper_file_identity(artifact)
        .map_err(|_| ServiceHelperGatePreflightError::Artifact)?;
    let mut reopened = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(artifact.path())
        .map_err(|_| ServiceHelperGatePreflightError::Artifact)?;
    let reopened_handle = HANDLE(reopened.as_raw_handle());
    authenticate_mapped_image(&held_before, reopened_handle)
        .map_err(|_| ServiceHelperGatePreflightError::Artifact)?;

    let length_before = reopened
        .metadata()
        .map_err(|_| ServiceHelperGatePreflightError::Artifact)?
        .len();
    if length_before == 0
        || length_before > MAX_SERVICE_HELPER_IMAGE_BYTES
        || artifact.identity().file_size != length_before
    {
        return Err(ServiceHelperGatePreflightError::Artifact);
    }
    let capacity =
        usize::try_from(length_before).map_err(|_| ServiceHelperGatePreflightError::Artifact)?;
    let mut bytes = Vec::with_capacity(capacity);
    reopened
        .by_ref()
        .take(MAX_SERVICE_HELPER_IMAGE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ServiceHelperGatePreflightError::Artifact)?;

    authenticate_mapped_image(&held_before, reopened_handle)
        .map_err(|_| ServiceHelperGatePreflightError::Artifact)?;
    let held_after = held_helper_file_identity(artifact)
        .map_err(|_| ServiceHelperGatePreflightError::Artifact)?;
    let length_after = reopened
        .metadata()
        .map_err(|_| ServiceHelperGatePreflightError::Artifact)?
        .len();
    if held_after != held_before
        || length_after != length_before
        || bytes.len() != capacity
        || artifact.identity().file_size != length_after
    {
        return Err(ServiceHelperGatePreflightError::Artifact);
    }

    parse_service_helper_gate_layout(&bytes)
}

fn parse_service_helper_gate_layout(
    bytes: &[u8],
) -> Result<ServiceHelperGateLayout, ServiceHelperGatePreflightError> {
    let capture = capture_gate_bytes();
    let adoption = adoption_complete_gate_bytes();
    parse_two_gate_layout(
        bytes,
        &capture,
        CAPTURE_GATE_BREAKPOINT_OFFSET,
        &adoption,
        ADOPTION_COMPLETE_GATE_BREAKPOINT_OFFSET,
    )
}

#[derive(Clone, Copy)]
struct GateOccurrence {
    raw_start: usize,
    raw_end: usize,
}

#[derive(Clone, Copy)]
struct LocatedGate {
    sequence: u32,
    breakpoint: u32,
    end: u32,
}

#[derive(Clone, Copy)]
struct PeSectionRange {
    raw_start: usize,
    raw_end: usize,
    initialized_raw_end: usize,
    virtual_start: u32,
    virtual_end: u32,
    characteristics: u32,
}

#[allow(clippy::too_many_lines)]
fn parse_two_gate_layout(
    bytes: &[u8],
    capture_sequence: &[u8],
    capture_breakpoint_offset: usize,
    adoption_sequence: &[u8],
    adoption_breakpoint_offset: usize,
) -> Result<ServiceHelperGateLayout, ServiceHelperGatePreflightError> {
    const DOS_HEADER_BYTES: usize = 64;
    const DOS_PE_OFFSET: usize = 0x3C;
    const COFF_HEADER_BYTES: usize = 20;
    const OPTIONAL_HEADER64_MINIMUM_BYTES: usize = 112;
    const SECTION_HEADER_BYTES: usize = 40;
    const MAX_PE_SECTIONS: usize = 96;
    const MAX_DATA_DIRECTORIES: u32 = 16;
    const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
    const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;
    const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
    const IMAGE_FILE_DLL: u16 = 0x2000;

    if bytes.len() < DOS_HEADER_BYTES
        || u64::try_from(bytes.len()).map_or(true, |length| length > MAX_SERVICE_HELPER_IMAGE_BYTES)
        || pe_u16(bytes, 0)? != 0x5A4D
    {
        return Err(ServiceHelperGatePreflightError::Image);
    }
    let pe_offset_u32 = pe_u32(bytes, DOS_PE_OFFSET)?;
    if pe_offset_u32 < u32::try_from(DOS_HEADER_BYTES).unwrap_or(u32::MAX)
        || pe_offset_u32 > i32::MAX.unsigned_abs()
        || pe_offset_u32 % 8 != 0
    {
        return Err(ServiceHelperGatePreflightError::Image);
    }
    let pe_offset =
        usize::try_from(pe_offset_u32).map_err(|_| ServiceHelperGatePreflightError::Image)?;
    let coff_offset = pe_offset
        .checked_add(4)
        .ok_or(ServiceHelperGatePreflightError::Image)?;
    let optional_offset = coff_offset
        .checked_add(COFF_HEADER_BYTES)
        .ok_or(ServiceHelperGatePreflightError::Image)?;
    if bytes.get(pe_offset..coff_offset) != Some(b"PE\0\0".as_slice())
        || pe_u16(bytes, coff_offset)? != IMAGE_FILE_MACHINE_AMD64
    {
        return Err(ServiceHelperGatePreflightError::Image);
    }

    let section_count = usize::from(pe_u16(bytes, coff_offset + 2)?);
    let optional_size = usize::from(pe_u16(bytes, coff_offset + 16)?);
    let file_characteristics = pe_u16(bytes, coff_offset + 18)?;
    if !(1..=MAX_PE_SECTIONS).contains(&section_count)
        || optional_size < OPTIONAL_HEADER64_MINIMUM_BYTES
        || file_characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0
        || file_characteristics & IMAGE_FILE_DLL != 0
        || pe_u16(bytes, optional_offset)? != IMAGE_NT_OPTIONAL_HDR64_MAGIC
    {
        return Err(ServiceHelperGatePreflightError::Image);
    }

    let optional_end = optional_offset
        .checked_add(optional_size)
        .ok_or(ServiceHelperGatePreflightError::Image)?;
    let directory_count = pe_u32(bytes, optional_offset + 108)?;
    let directory_bytes = usize::try_from(directory_count)
        .map_err(|_| ServiceHelperGatePreflightError::Image)?
        .checked_mul(8)
        .ok_or(ServiceHelperGatePreflightError::Image)?;
    if directory_count > MAX_DATA_DIRECTORIES
        || OPTIONAL_HEADER64_MINIMUM_BYTES
            .checked_add(directory_bytes)
            .is_none_or(|minimum| minimum > optional_size)
    {
        return Err(ServiceHelperGatePreflightError::Image);
    }
    let section_table_bytes = section_count
        .checked_mul(SECTION_HEADER_BYTES)
        .ok_or(ServiceHelperGatePreflightError::Image)?;
    let section_table_end = optional_end
        .checked_add(section_table_bytes)
        .ok_or(ServiceHelperGatePreflightError::Image)?;
    let section_alignment = pe_u32(bytes, optional_offset + 32)?;
    let file_alignment = pe_u32(bytes, optional_offset + 36)?;
    let size_of_image = pe_u32(bytes, optional_offset + 56)?;
    let size_of_headers = pe_u32(bytes, optional_offset + 60)?;
    let size_of_headers_usize =
        usize::try_from(size_of_headers).map_err(|_| ServiceHelperGatePreflightError::Image)?;
    if section_alignment == 0
        || !(0x200..=0x1_0000).contains(&file_alignment)
        || !section_alignment.is_power_of_two()
        || !file_alignment.is_power_of_two()
        || section_alignment < file_alignment
        || (section_alignment < 0x1000 && section_alignment != file_alignment)
        || size_of_image == 0
        || u64::from(size_of_image) > MAX_SERVICE_HELPER_IMAGE_BYTES
        || size_of_headers == 0
        || size_of_headers > size_of_image
        || size_of_headers % file_alignment != 0
        || section_table_end > size_of_headers_usize
        || size_of_headers_usize > bytes.len()
        || size_of_image % section_alignment != 0
    {
        return Err(ServiceHelperGatePreflightError::Image);
    }
    let first_section_rva = align_up(size_of_headers, section_alignment)
        .ok_or(ServiceHelperGatePreflightError::Image)?;

    let capture = find_unique(bytes, capture_sequence)?;
    let adoption = find_unique(bytes, adoption_sequence)?;
    if ranges_overlap(
        (capture.raw_start, capture.raw_end),
        (adoption.raw_start, adoption.raw_end),
    ) {
        return Err(ServiceHelperGatePreflightError::Image);
    }

    let mut sections: Vec<PeSectionRange> = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let section_offset = optional_end
            .checked_add(
                index
                    .checked_mul(SECTION_HEADER_BYTES)
                    .ok_or(ServiceHelperGatePreflightError::Image)?,
            )
            .ok_or(ServiceHelperGatePreflightError::Image)?;
        let virtual_size = pe_u32(bytes, section_offset + 8)?;
        let virtual_start = pe_u32(bytes, section_offset + 12)?;
        let raw_size = pe_u32(bytes, section_offset + 16)?;
        let raw_start_u32 = pe_u32(bytes, section_offset + 20)?;
        let characteristics = pe_u32(bytes, section_offset + 36)?;
        let raw_start =
            usize::try_from(raw_start_u32).map_err(|_| ServiceHelperGatePreflightError::Image)?;
        let raw_size_usize =
            usize::try_from(raw_size).map_err(|_| ServiceHelperGatePreflightError::Image)?;
        let raw_end = raw_start
            .checked_add(raw_size_usize)
            .ok_or(ServiceHelperGatePreflightError::Image)?;
        let initialized_raw_length = usize::try_from(virtual_size.min(raw_size))
            .map_err(|_| ServiceHelperGatePreflightError::Image)?;
        let initialized_raw_end = raw_start
            .checked_add(initialized_raw_length)
            .ok_or(ServiceHelperGatePreflightError::Image)?;
        let mapped_size = virtual_size.max(raw_size);
        let virtual_end = virtual_start
            .checked_add(mapped_size)
            .ok_or(ServiceHelperGatePreflightError::Image)?;
        if mapped_size == 0
            || virtual_start < first_section_rva
            || virtual_start % section_alignment != 0
            || (raw_size == 0 && raw_start_u32 != 0)
            || (raw_size != 0
                && (raw_start_u32 % file_alignment != 0
                    || raw_size % file_alignment != 0
                    || raw_start < size_of_headers_usize
                    || raw_end > bytes.len()))
            || virtual_end > size_of_image
        {
            return Err(ServiceHelperGatePreflightError::Image);
        }
        let section = PeSectionRange {
            raw_start,
            raw_end,
            initialized_raw_end,
            virtual_start,
            virtual_end,
            characteristics,
        };
        for prior in &sections {
            if (section.raw_start != section.raw_end
                && prior.raw_start != prior.raw_end
                && ranges_overlap(
                    (section.raw_start, section.raw_end),
                    (prior.raw_start, prior.raw_end),
                ))
                || ranges_overlap(
                    (section.virtual_start, section.virtual_end),
                    (prior.virtual_start, prior.virtual_end),
                )
            {
                return Err(ServiceHelperGatePreflightError::Image);
            }
        }
        sections.push(section);
    }

    let capture = locate_gate(
        capture,
        capture_sequence,
        capture_breakpoint_offset,
        &sections,
        size_of_image,
    )?;
    let adoption = locate_gate(
        adoption,
        adoption_sequence,
        adoption_breakpoint_offset,
        &sections,
        size_of_image,
    )?;
    if capture.sequence == adoption.sequence
        || ranges_overlap(
            (capture.sequence, capture.end),
            (adoption.sequence, adoption.end),
        )
    {
        return Err(ServiceHelperGatePreflightError::Image);
    }

    Ok(ServiceHelperGateLayout {
        capture_sequence_rva: capture.sequence,
        capture_breakpoint_rva: capture.breakpoint,
        adoption_sequence_rva: adoption.sequence,
        adoption_breakpoint_rva: adoption.breakpoint,
        size_of_image,
    })
}

fn find_unique(
    bytes: &[u8],
    sequence: &[u8],
) -> Result<GateOccurrence, ServiceHelperGatePreflightError> {
    if sequence.is_empty() {
        return Err(ServiceHelperGatePreflightError::Image);
    }
    let mut occurrences = bytes
        .windows(sequence.len())
        .enumerate()
        .filter_map(|(offset, candidate)| (candidate == sequence).then_some(offset));
    let raw_start = occurrences
        .next()
        .ok_or(ServiceHelperGatePreflightError::Image)?;
    if occurrences.next().is_some() {
        return Err(ServiceHelperGatePreflightError::Image);
    }
    let raw_end = raw_start
        .checked_add(sequence.len())
        .ok_or(ServiceHelperGatePreflightError::Image)?;
    Ok(GateOccurrence { raw_start, raw_end })
}

fn locate_gate(
    occurrence: GateOccurrence,
    sequence: &[u8],
    breakpoint_offset: usize,
    sections: &[PeSectionRange],
    size_of_image: u32,
) -> Result<LocatedGate, ServiceHelperGatePreflightError> {
    const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
    const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

    if sequence.get(breakpoint_offset) != Some(&0xCC) {
        return Err(ServiceHelperGatePreflightError::Image);
    }
    let mut located = None;
    for section in sections {
        if occurrence.raw_start < section.raw_start || occurrence.raw_end > section.raw_end {
            continue;
        }
        if section.characteristics & IMAGE_SCN_CNT_CODE == 0
            || section.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0
            || section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0
            || section.characteristics & IMAGE_SCN_MEM_WRITE != 0
            || occurrence.raw_end > section.initialized_raw_end
        {
            return Err(ServiceHelperGatePreflightError::Image);
        }
        let delta = occurrence
            .raw_start
            .checked_sub(section.raw_start)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(ServiceHelperGatePreflightError::Image)?;
        let sequence_rva = section
            .virtual_start
            .checked_add(delta)
            .ok_or(ServiceHelperGatePreflightError::Image)?;
        let sequence_end_rva = sequence_rva
            .checked_add(
                u32::try_from(sequence.len())
                    .map_err(|_| ServiceHelperGatePreflightError::Image)?,
            )
            .ok_or(ServiceHelperGatePreflightError::Image)?;
        let breakpoint_rva = sequence_rva
            .checked_add(
                u32::try_from(breakpoint_offset)
                    .map_err(|_| ServiceHelperGatePreflightError::Image)?,
            )
            .ok_or(ServiceHelperGatePreflightError::Image)?;
        if sequence_end_rva > section.virtual_end
            || sequence_end_rva > size_of_image
            || breakpoint_rva >= sequence_end_rva
            || located
                .replace(LocatedGate {
                    sequence: sequence_rva,
                    breakpoint: breakpoint_rva,
                    end: sequence_end_rva,
                })
                .is_some()
        {
            return Err(ServiceHelperGatePreflightError::Image);
        }
    }
    located.ok_or(ServiceHelperGatePreflightError::Image)
}

fn pe_u16(bytes: &[u8], offset: usize) -> Result<u16, ServiceHelperGatePreflightError> {
    let end = offset
        .checked_add(size_of::<u16>())
        .ok_or(ServiceHelperGatePreflightError::Image)?;
    let value: [u8; 2] = bytes
        .get(offset..end)
        .ok_or(ServiceHelperGatePreflightError::Image)?
        .try_into()
        .map_err(|_| ServiceHelperGatePreflightError::Image)?;
    Ok(u16::from_le_bytes(value))
}

fn pe_u32(bytes: &[u8], offset: usize) -> Result<u32, ServiceHelperGatePreflightError> {
    let end = offset
        .checked_add(size_of::<u32>())
        .ok_or(ServiceHelperGatePreflightError::Image)?;
    let value: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(ServiceHelperGatePreflightError::Image)?
        .try_into()
        .map_err(|_| ServiceHelperGatePreflightError::Image)?;
    Ok(u32::from_le_bytes(value))
}

fn align_up(value: u32, alignment: u32) -> Option<u32> {
    value
        .checked_add(alignment.checked_sub(1)?)
        .map(|rounded| rounded & !(alignment - 1))
}

fn ranges_overlap<T: Ord + Copy>(first: (T, T), second: (T, T)) -> bool {
    first.0 < second.1 && second.0 < first.1
}

#[cfg(test)]
mod tests {
    use key_agent_service_helper_bootstrap::{
        ADOPTION_COMPLETE_GATE_BREAKPOINT_OFFSET, ADOPTION_COMPLETE_GATE_BYTES,
        CAPTURE_GATE_BREAKPOINT_OFFSET, CAPTURE_GATE_BYTES, adoption_complete_gate_bytes,
        capture_gate_bytes,
    };

    use super::{
        ServiceHelperGatePreflightError, parse_service_helper_gate_layout, parse_two_gate_layout,
    };

    const IMAGE_BYTES: usize = 0x600;
    const PE_OFFSET: usize = 0x80;
    const COFF_OFFSET: usize = PE_OFFSET + 4;
    const OPTIONAL_OFFSET: usize = COFF_OFFSET + 20;
    const OPTIONAL_BYTES: usize = 0xF0;
    const SECTION_OFFSET: usize = OPTIONAL_OFFSET + OPTIONAL_BYTES;
    const TEXT_RAW_START: usize = 0x200;
    const TEXT_RVA: u32 = 0x1000;
    const CAPTURE_RAW_START: usize = 0x220;
    const ADOPTION_RAW_START: usize = 0x280;

    fn valid_image() -> Vec<u8> {
        let mut image = vec![0_u8; IMAGE_BYTES];
        image[0..2].copy_from_slice(b"MZ");
        put_u32(&mut image, 0x3C, u32::try_from(PE_OFFSET).unwrap_or(0));
        image[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
        put_u16(&mut image, COFF_OFFSET, 0x8664);
        put_u16(&mut image, COFF_OFFSET + 2, 2);
        put_u16(
            &mut image,
            COFF_OFFSET + 16,
            u16::try_from(OPTIONAL_BYTES).unwrap_or(0),
        );
        put_u16(&mut image, COFF_OFFSET + 18, 0x0022);

        put_u16(&mut image, OPTIONAL_OFFSET, 0x020B);
        put_u32(&mut image, OPTIONAL_OFFSET + 32, 0x1000);
        put_u32(&mut image, OPTIONAL_OFFSET + 36, 0x200);
        put_u32(&mut image, OPTIONAL_OFFSET + 56, 0x3000);
        put_u32(&mut image, OPTIONAL_OFFSET + 60, 0x200);
        put_u32(&mut image, OPTIONAL_OFFSET + 108, 16);

        image[SECTION_OFFSET..SECTION_OFFSET + 8].copy_from_slice(b".text\0\0\0");
        put_u32(&mut image, SECTION_OFFSET + 8, 0x180);
        put_u32(&mut image, SECTION_OFFSET + 12, TEXT_RVA);
        put_u32(&mut image, SECTION_OFFSET + 16, 0x200);
        put_u32(&mut image, SECTION_OFFSET + 20, 0x200);
        put_u32(&mut image, SECTION_OFFSET + 36, 0x6000_0020);

        let data = SECTION_OFFSET + 40;
        image[data..data + 8].copy_from_slice(b".rdata\0\0");
        put_u32(&mut image, data + 8, 0x100);
        put_u32(&mut image, data + 12, 0x2000);
        put_u32(&mut image, data + 16, 0x200);
        put_u32(&mut image, data + 20, 0x400);
        put_u32(&mut image, data + 36, 0x4000_0040);

        image[CAPTURE_RAW_START..CAPTURE_RAW_START + CAPTURE_GATE_BYTES]
            .copy_from_slice(&capture_gate_bytes());
        image[ADOPTION_RAW_START..ADOPTION_RAW_START + ADOPTION_COMPLETE_GATE_BYTES]
            .copy_from_slice(&adoption_complete_gate_bytes());
        image
    }

    #[test]
    fn valid_fixture_binds_exact_sequence_breakpoint_and_image_rvas() {
        let layout = parse_service_helper_gate_layout(&valid_image())
            .unwrap_or_else(|error| unreachable!("valid two-gate fixture was rejected: {error:?}"));
        assert_eq!(layout.capture_sequence_rva(), 0x1020);
        assert_eq!(layout.capture_breakpoint_rva(), 0x1034);
        assert_eq!(layout.adoption_sequence_rva(), 0x1080);
        assert_eq!(layout.adoption_breakpoint_rva(), 0x1094);
        assert_eq!(layout.size_of_image(), 0x3000);
        assert_eq!(CAPTURE_GATE_BREAKPOINT_OFFSET, 20);
        assert_eq!(ADOPTION_COMPLETE_GATE_BREAKPOINT_OFFSET, 20);
    }

    #[test]
    fn every_truncated_prefix_is_rejected() {
        let image = valid_image();
        for length in 0..image.len() {
            assert!(parse_service_helper_gate_layout(&image[..length]).is_err());
        }
        assert!(parse_service_helper_gate_layout(&image).is_ok());
    }

    #[test]
    fn duplicate_of_either_exact_sequence_anywhere_in_file_is_rejected() {
        let mut duplicate_capture = valid_image();
        duplicate_capture[0x420..0x420 + CAPTURE_GATE_BYTES].copy_from_slice(&capture_gate_bytes());
        assert!(parse_service_helper_gate_layout(&duplicate_capture).is_err());

        let mut duplicate_adoption = valid_image();
        duplicate_adoption[0x460..0x460 + ADOPTION_COMPLETE_GATE_BYTES]
            .copy_from_slice(&adoption_complete_gate_bytes());
        assert!(parse_service_helper_gate_layout(&duplicate_adoption).is_err());
    }

    #[test]
    fn absence_and_every_single_byte_gate_mutation_are_rejected() {
        for index in 0..CAPTURE_GATE_BYTES {
            let mut mutated = valid_image();
            mutated[CAPTURE_RAW_START + index] ^= 1;
            assert!(parse_service_helper_gate_layout(&mutated).is_err());
        }
        for index in 0..ADOPTION_COMPLETE_GATE_BYTES {
            let mut mutated = valid_image();
            mutated[ADOPTION_RAW_START + index] ^= 1;
            assert!(parse_service_helper_gate_layout(&mutated).is_err());
        }

        let mut absent = valid_image();
        absent[CAPTURE_RAW_START..CAPTURE_RAW_START + CAPTURE_GATE_BYTES].fill(0);
        absent[ADOPTION_RAW_START..ADOPTION_RAW_START + ADOPTION_COMPLETE_GATE_BYTES].fill(0);
        assert!(parse_service_helper_gate_layout(&absent).is_err());
    }

    #[test]
    fn wrong_machine_optional_magic_and_file_flags_are_rejected() {
        for mutate in [
            |image: &mut Vec<u8>| put_u16(image, COFF_OFFSET, 0x014C),
            |image: &mut Vec<u8>| put_u16(image, OPTIONAL_OFFSET, 0x010B),
            |image: &mut Vec<u8>| put_u16(image, COFF_OFFSET + 18, 0x0020),
            |image: &mut Vec<u8>| put_u16(image, COFF_OFFSET + 18, 0x2022),
        ] {
            let mut image = valid_image();
            mutate(&mut image);
            assert!(parse_service_helper_gate_layout(&image).is_err());
        }
    }

    #[test]
    fn wrong_code_section_flags_are_rejected() {
        for characteristics in [0x6000_0000, 0x4000_0020, 0xE000_0020, 0x6000_00A0] {
            let mut image = valid_image();
            put_u32(&mut image, SECTION_OFFSET + 36, characteristics);
            assert!(parse_service_helper_gate_layout(&image).is_err());
        }
    }

    #[test]
    fn gate_in_uninitialized_raw_tail_or_across_section_boundary_is_rejected() {
        let mut uninitialized_tail = valid_image();
        put_u32(&mut uninitialized_tail, SECTION_OFFSET + 8, 0x9B);
        assert!(parse_service_helper_gate_layout(&uninitialized_tail).is_err());

        let mut split = valid_image();
        split[CAPTURE_RAW_START..CAPTURE_RAW_START + CAPTURE_GATE_BYTES].fill(0);
        split[0x3F0..0x3F0 + CAPTURE_GATE_BYTES].copy_from_slice(&capture_gate_bytes());
        assert!(parse_service_helper_gate_layout(&split).is_err());
    }

    #[test]
    fn overlapping_and_overflowing_section_ranges_are_rejected() {
        let data = SECTION_OFFSET + 40;

        let mut raw_overlap = valid_image();
        put_u32(&mut raw_overlap, data + 20, 0x200);
        assert!(parse_service_helper_gate_layout(&raw_overlap).is_err());

        let mut virtual_overlap = valid_image();
        put_u32(&mut virtual_overlap, data + 12, 0x1000);
        assert!(parse_service_helper_gate_layout(&virtual_overlap).is_err());

        let mut endpoint_overflow = valid_image();
        put_u32(&mut endpoint_overflow, SECTION_OFFSET + 8, 0x2000);
        put_u32(&mut endpoint_overflow, SECTION_OFFSET + 12, 0xFFFF_F000);
        assert!(parse_service_helper_gate_layout(&endpoint_overflow).is_err());

        let mut outside_image = valid_image();
        put_u32(&mut outside_image, OPTIONAL_OFFSET + 56, 0x2000);
        assert!(parse_service_helper_gate_layout(&outside_image).is_err());
    }

    #[test]
    fn malformed_header_and_section_ranges_are_rejected() {
        for mutate in [
            |image: &mut Vec<u8>| put_u32(image, 0x3C, 0x7F),
            |image: &mut Vec<u8>| put_u16(image, COFF_OFFSET + 2, 0),
            |image: &mut Vec<u8>| put_u16(image, COFF_OFFSET + 16, 111),
            |image: &mut Vec<u8>| put_u32(image, OPTIONAL_OFFSET + 108, 17),
            |image: &mut Vec<u8>| put_u32(image, OPTIONAL_OFFSET + 36, 0x100),
            |image: &mut Vec<u8>| put_u32(image, OPTIONAL_OFFSET + 60, 0x201),
            |image: &mut Vec<u8>| put_u32(image, SECTION_OFFSET + 20, 0x201),
            |image: &mut Vec<u8>| put_u32(image, SECTION_OFFSET + 12, 0x1100),
        ] {
            let mut image = valid_image();
            mutate(&mut image);
            assert!(parse_service_helper_gate_layout(&image).is_err());
        }
    }

    #[test]
    fn overlapping_sequences_and_invalid_breakpoint_offsets_are_rejected() {
        let mut image = valid_image();
        let raw_start = 0x320;
        let capture = [0xA1, 0xA2, 0xCC, 0xA4];
        let adoption = [0xCC, 0xA4, 0xB1];
        image[raw_start..raw_start + 5].copy_from_slice(&[0xA1, 0xA2, 0xCC, 0xA4, 0xB1]);
        assert!(parse_two_gate_layout(&image, &capture, 2, &adoption, 0).is_err());

        assert!(
            parse_two_gate_layout(
                &valid_image(),
                &capture_gate_bytes(),
                CAPTURE_GATE_BYTES,
                &adoption_complete_gate_bytes(),
                ADOPTION_COMPLETE_GATE_BREAKPOINT_OFFSET,
            )
            .is_err()
        );
    }

    #[test]
    fn layout_and_errors_have_redacted_diagnostics() {
        let layout = parse_service_helper_gate_layout(&valid_image())
            .unwrap_or_else(|error| unreachable!("valid two-gate fixture was rejected: {error:?}"));
        assert_eq!(
            format!("{layout:?}"),
            "ServiceHelperGateLayout([REDACTED TWO-GATE RVAS])"
        );
        assert_eq!(
            format!("{:?}", ServiceHelperGatePreflightError::Artifact),
            "Artifact"
        );
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}
