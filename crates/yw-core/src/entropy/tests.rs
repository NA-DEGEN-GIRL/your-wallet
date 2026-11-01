//! spec/02 §11.1 (the vault-level cases `create_draws_entropy_first` and
//! `rng_failure_aborts_without_commit` live in `vault/tests.rs`).

use super::{
    FailingRandom, RandomSource, ScriptedRandom, random_array_with, random_below_with,
    random_nonzero_id_with, random_secret32_with, secp_context,
};
use crate::bip39::Mnemonic;
use crate::error::KeyError;

#[test]
fn stuck_rng_rejected() {
    for stuck in [0x00_u8, 0x5a] {
        let mut rng = ScriptedRandom::new(&[stuck; 32]);
        assert_eq!(
            random_secret32_with(&mut rng).err(),
            Some(KeyError::RandomnessUnavailable)
        );
        let mut rng = ScriptedRandom::new(&[stuck; 32]);
        assert_eq!(
            Mnemonic::generate_with_rng(&mut rng).err(),
            Some(KeyError::RandomnessUnavailable)
        );
    }
    let mut almost = [0x5a_u8; 32];
    almost[31] = 0x5b;
    let mut rng = ScriptedRandom::new(&almost);
    assert_eq!(
        random_secret32_with(&mut rng).unwrap().as_slice(),
        almost.as_slice()
    );
}

#[test]
fn stuck_rng_rejected_for_salts_and_nonces() {
    // Review L16: the salt/nonce helper applies the same all-equal check as the DEK.
    for stuck in [0x00_u8, 0x5a, 0xff] {
        let mut rng = ScriptedRandom::new(&[stuck; 24]);
        assert_eq!(
            random_array_with::<24>(&mut rng),
            Err(KeyError::RandomnessUnavailable)
        );
        let mut rng = ScriptedRandom::new(&[stuck; 16]);
        assert_eq!(
            random_array_with::<16>(&mut rng),
            Err(KeyError::RandomnessUnavailable)
        );
    }
    let mut almost = [0x5a_u8; 24];
    almost[0] = 0x00;
    let mut rng = ScriptedRandom::new(&almost);
    assert_eq!(random_array_with::<24>(&mut rng), Ok(almost));
}

#[test]
fn zero_id_redrawn_then_fails() {
    let mut rng = ScriptedRandom::new(&[0_u8; 64]);
    assert_eq!(
        random_nonzero_id_with(&mut rng),
        Err(KeyError::RandomnessUnavailable)
    );
    assert_eq!(rng.consumed, 64);

    let mut script = vec![0_u8; 48];
    script.extend_from_slice(&[7_u8; 16]);
    let mut rng = ScriptedRandom::new(&script);
    assert_eq!(random_nonzero_id_with(&mut rng), Ok([7_u8; 16]));
    assert_eq!(rng.consumed, 64);
}

#[test]
fn secp_context_consumes_32_bytes() {
    let mut rng = ScriptedRandom::new(&[]);
    let _ctx = secp_context(&mut rng).unwrap();
    assert_eq!(rng.consumed, 32);
}

#[test]
fn failing_source_propagates_without_fallback() {
    assert_eq!(
        secp_context(&mut FailingRandom).err(),
        Some(KeyError::RandomnessUnavailable)
    );
    assert_eq!(
        random_nonzero_id_with(&mut FailingRandom),
        Err(KeyError::RandomnessUnavailable)
    );
    assert_eq!(
        random_below_with(&mut FailingRandom, 24),
        Err(KeyError::RandomnessUnavailable)
    );
    assert_eq!(
        random_array_with::<24>(&mut FailingRandom),
        Err(KeyError::RandomnessUnavailable)
    );
    assert_eq!(
        Mnemonic::generate_with_rng(&mut FailingRandom).err(),
        Some(KeyError::RandomnessUnavailable)
    );
}

#[test]
fn random_below_rejects_the_biased_tail() {
    // upper = 24: acceptance = u32::MAX - (u32::MAX % 24) = 0xFFFF_FFF0. 0xFFFF_FFFF is redrawn.
    let mut script = 0xffff_ffff_u32.to_le_bytes().to_vec();
    script.extend_from_slice(&50_u32.to_le_bytes());
    let mut rng = ScriptedRandom::new(&script);
    assert_eq!(random_below_with(&mut rng, 24), Ok(2));
    assert_eq!(rng.consumed, 8);
    assert_eq!(
        random_below_with(&mut ScriptedRandom::new(&[]), 0),
        Err(KeyError::Internal)
    );
    assert_eq!(
        random_below_with(&mut ScriptedRandom::new(&5_u32.to_le_bytes()), 1),
        Ok(0)
    );
}

#[test]
fn os_random_fills() {
    let mut a = [0_u8; 32];
    let mut b = [0_u8; 32];
    super::OsRandom.fill(&mut a).unwrap();
    super::fill_random(&mut b).unwrap();
    assert_ne!(a, b);
    assert_ne!(super::random_nonzero_id().unwrap(), [0; 16]);
    assert!(super::random_below(24).unwrap() < 24);
}
