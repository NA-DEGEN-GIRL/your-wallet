//! Program-derived addresses and associated token accounts (spec/07 §8.4).

use core::fmt;

use sha2::{Digest, Sha256};

use super::address::{ATA_PROGRAM, SolAddress, is_on_curve_solana};

/// Maximum number of seeds.
pub const MAX_SEEDS: usize = 16;
/// Maximum length of one seed.
pub const MAX_SEED_LEN: usize = 32;
const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";

/// PDA derivation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PdaError {
    /// More than 16 seeds or a seed longer than 32 bytes.
    BadSeeds,
    /// The hash is a curve point (not a valid PDA).
    OnCurve,
    /// No bump in 255..=1 gave an off-curve address (practically impossible).
    NoBump,
}

impl fmt::Display for PdaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BadSeeds => "invalid PDA seeds",
            Self::OnCurve => "PDA hash is on the curve",
            Self::NoBump => "no valid PDA bump",
        })
    }
}

impl std::error::Error for PdaError {}

/// `SHA-256(seed_1 ‖ … ‖ seed_n ‖ program ‖ "ProgramDerivedAddress")`, rejected when on curve.
///
/// # Errors
///
/// [`PdaError::BadSeeds`] or [`PdaError::OnCurve`].
pub fn create_program_address(
    seeds: &[&[u8]],
    program: &SolAddress,
) -> Result<SolAddress, PdaError> {
    if seeds.len() > MAX_SEEDS || seeds.iter().any(|seed| seed.len() > MAX_SEED_LEN) {
        return Err(PdaError::BadSeeds);
    }
    let mut hasher = Sha256::new();
    for seed in seeds {
        hasher.update(seed);
    }
    hasher.update(program.as_bytes());
    hasher.update(PDA_MARKER);
    let hash: [u8; 32] = hasher.finalize().into();
    if is_on_curve_solana(&hash) {
        return Err(PdaError::OnCurve);
    }
    Ok(SolAddress::from_bytes(hash))
}

/// Tries bumps 255, 254, …, 1 (`seeds ‖ [bump]`) and returns the first valid PDA.
///
/// # Errors
///
/// [`PdaError::BadSeeds`] (a 16th seed slot is needed for the bump) or [`PdaError::NoBump`].
pub fn find_program_address(
    seeds: &[&[u8]],
    program: &SolAddress,
) -> Result<(SolAddress, u8), PdaError> {
    if seeds.len() >= MAX_SEEDS {
        return Err(PdaError::BadSeeds);
    }
    for bump in (1..=u8::MAX).rev() {
        let bump_seed = [bump];
        let mut with_bump: Vec<&[u8]> = seeds.to_vec();
        with_bump.push(&bump_seed);
        match create_program_address(&with_bump, program) {
            Ok(address) => return Ok((address, bump)),
            Err(PdaError::OnCurve) => {}
            Err(other) => return Err(other),
        }
    }
    Err(PdaError::NoBump)
}

/// The associated token account of `wallet` for `mint` under `token_program`
/// (seeds `[wallet, token_program, mint]`, program = ATA).
///
/// # Errors
///
/// [`PdaError::NoBump`].
pub fn associated_token_address(
    wallet: &SolAddress,
    token_program: &SolAddress,
    mint: &SolAddress,
) -> Result<(SolAddress, u8), PdaError> {
    find_program_address(
        &[wallet.as_bytes(), token_program.as_bytes(), mint.as_bytes()],
        &ATA_PROGRAM,
    )
}

#[cfg(test)]
mod tests {
    use super::{PdaError, associated_token_address, create_program_address, find_program_address};
    use crate::sol::address::{SolAddress, TOKEN_PROGRAM, is_on_curve_solana};

    fn addr(text: &str) -> SolAddress {
        SolAddress::parse(text).unwrap()
    }

    #[test]
    fn solana_sdk_create_program_address_vectors() {
        let program = addr("BPFLoaderUpgradeab1e11111111111111111111111");
        let public = addr("SeedPubey1111111111111111111111111111111111");
        assert_eq!(
            create_program_address(&[b"", &[1]], &program).unwrap(),
            addr("BwqrghZA2htAcqq8dzP1WDAhTXYTYWj7CHxF5j7TDBAe")
        );
        assert_eq!(
            create_program_address(&["☉".as_bytes(), &[0]], &program).unwrap(),
            addr("13yWmRpaTR4r5nAktwLqMpRNr28tnVUZw26rTvPSSB19")
        );
        assert_eq!(
            create_program_address(&[b"Talking", b"Squirrels"], &program).unwrap(),
            addr("2fnQrngrQT4SeLcdToJAD96phoEjNL2man2kfRLCASVk")
        );
        assert_eq!(
            create_program_address(&[public.as_bytes(), &[1]], &program).unwrap(),
            addr("976ymqVnfE32QFe6NfGDctSvVa36LWnvYxhU6G2232YL")
        );
        assert_eq!(
            create_program_address(&[&[0_u8; 33]], &program),
            Err(PdaError::BadSeeds)
        );
        let many: Vec<&[u8]> = vec![b"x"; 17];
        assert_eq!(
            create_program_address(&many, &program),
            Err(PdaError::BadSeeds)
        );
        let (found, bump) = find_program_address(&[b"Lil'", b"Bits"], &program).unwrap();
        assert_eq!(
            create_program_address(&[b"Lil'", b"Bits", &[bump]], &program).unwrap(),
            found
        );
    }

    #[test]
    fn usdc_ata_of_the_abandon_account() {
        let wallet = addr("HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk");
        let mint = addr("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
        let (ata, bump) = associated_token_address(&wallet, &TOKEN_PROGRAM, &mint).unwrap();
        assert_eq!(ata, addr("5N3f1tj9v1vc5TUZ8S7mCAnVmjVKrfnzXWhxLaxyZAgt"));
        assert_eq!(bump, 254);
        assert!(!is_on_curve_solana(ata.as_bytes()));
        let to = addr("Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb");
        let (to_ata, to_bump) = associated_token_address(&to, &TOKEN_PROGRAM, &mint).unwrap();
        assert_eq!(to_ata, addr("8X8ts1CnpZmtqApE2rREA97xEJuSRcomPGVcMFdS2cgY"));
        assert_eq!(to_bump, 255);
    }
}
