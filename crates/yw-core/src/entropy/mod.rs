//! Randomness (spec/02 §1). The only OS call in yw-core is `getrandom::fill` here.
//!
//! Fail-closed: a failed or stuck draw aborts the whole operation with
//! [`KeyError::RandomnessUnavailable`]; there is no retry inside the operation and no fallback
//! source. Injection of a [`RandomSource`] is `pub(crate)` only (`*_with` functions); public
//! functions always use [`OsRandom`].

use secp256k1::{All, Secp256k1};
use zeroize::Zeroizing;

use crate::error::KeyError;

/// Attempts for a non-zero 16-byte identifier before giving up (archive `fill_random_nonzero`).
const NONZERO_ID_ATTEMPTS: usize = 4;
/// Bound on rejection-sampling rounds; each round is accepted with probability above 1/2.
const BELOW_ATTEMPTS: usize = 128;

/// A source of random bytes.
pub(crate) trait RandomSource {
    /// Fills `out` completely or fails.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), KeyError>;
}

/// The OS CSPRNG (`getrandom`, Windows `ProcessPrng`).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), KeyError> {
        getrandom::fill(out).map_err(|_| KeyError::RandomnessUnavailable)
    }
}

/// A fresh secp256k1 context randomized with 32 bytes from `rng` (spec/02 §1.3).
/// This is the only way yw-core creates a context; callers drop it after the operation.
pub(crate) fn secp_context(rng: &mut impl RandomSource) -> Result<Secp256k1<All>, KeyError> {
    let mut ctx = Secp256k1::new();
    let mut seed = Zeroizing::new([0_u8; 32]);
    rng.fill(seed.as_mut())?;
    ctx.seeded_randomize(&seed);
    Ok(ctx)
}

/// Fills `out` from the OS CSPRNG.
///
/// # Errors
///
/// [`KeyError::RandomnessUnavailable`] if the OS source fails.
pub fn fill_random(out: &mut [u8]) -> Result<(), KeyError> {
    OsRandom.fill(out)
}

/// A random non-zero 16-byte identifier from the OS CSPRNG.
///
/// # Errors
///
/// [`KeyError::RandomnessUnavailable`] if the OS source fails or returns zero four times.
pub fn random_nonzero_id() -> Result<[u8; 16], KeyError> {
    random_nonzero_id_with(&mut OsRandom)
}

/// A uniform value in `0..upper` from the OS CSPRNG (rejection sampling over `u32`).
///
/// # Errors
///
/// [`KeyError::Internal`] if `upper` is 0; [`KeyError::RandomnessUnavailable`] if the source fails.
pub fn random_below(upper: u32) -> Result<u32, KeyError> {
    random_below_with(&mut OsRandom, upper)
}

pub(crate) fn random_nonzero_id_with(rng: &mut impl RandomSource) -> Result<[u8; 16], KeyError> {
    for _ in 0..NONZERO_ID_ATTEMPTS {
        let mut id = [0_u8; 16];
        rng.fill(&mut id)?;
        if id != [0_u8; 16] {
            return Ok(id);
        }
    }
    Err(KeyError::RandomnessUnavailable)
}

pub(crate) fn random_below_with(rng: &mut impl RandomSource, upper: u32) -> Result<u32, KeyError> {
    if upper == 0 {
        return Err(KeyError::Internal);
    }
    let acceptance = u32::MAX - (u32::MAX % upper);
    for _ in 0..BELOW_ATTEMPTS {
        let mut bytes = [0_u8; 4];
        rng.fill(&mut bytes)?;
        let candidate = u32::from_le_bytes(bytes);
        if candidate < acceptance {
            return Ok(candidate % upper);
        }
    }
    Err(KeyError::RandomnessUnavailable)
}

/// 32 secret random bytes (mnemonic entropy, DEK). All-equal output is treated as a stuck source.
pub(crate) fn random_secret32_with(
    rng: &mut impl RandomSource,
) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let mut out = Zeroizing::new([0_u8; 32]);
    rng.fill(out.as_mut())?;
    let first = out.first().copied().unwrap_or(0);
    if out.iter().all(|byte| *byte == first) {
        return Err(KeyError::RandomnessUnavailable);
    }
    Ok(out)
}

/// `N` random bytes for salts and nonces (`N` is 16 or 24 at every call site).
///
/// All-equal output is treated as a stuck source, exactly like [`random_secret32_with`]: a nonce
/// source that is stuck mid-session would otherwise reuse an `XChaCha20` nonce under the same DEK
/// (review L16). For `N >= 16` an honest source produces all-equal bytes with probability
/// `2^-(8(N-1))`, so the check never fires in practice.
pub(crate) fn random_array_with<const N: usize>(
    rng: &mut impl RandomSource,
) -> Result<[u8; N], KeyError> {
    let mut out = [0_u8; N];
    rng.fill(&mut out)?;
    let first = out.first().copied().unwrap_or(0);
    if N >= 2 && out.iter().all(|byte| *byte == first) {
        return Err(KeyError::RandomnessUnavailable);
    }
    Ok(out)
}

/// Test source: returns `script` first, then a deterministic counter sequence; counts bytes.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct ScriptedRandom {
    script: Vec<u8>,
    position: usize,
    counter: u8,
    pub(crate) consumed: usize,
}

#[cfg(test)]
impl ScriptedRandom {
    pub(crate) fn new(script: &[u8]) -> Self {
        Self {
            script: script.to_vec(),
            position: 0,
            counter: 0x80,
            consumed: 0,
        }
    }
}

#[cfg(test)]
impl RandomSource for ScriptedRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), KeyError> {
        for byte in out.iter_mut() {
            if let Some(next) = self.script.get(self.position) {
                *byte = *next;
                self.position += 1;
            } else {
                *byte = self.counter;
                self.counter = self.counter.wrapping_add(0x3b);
            }
        }
        self.consumed += out.len();
        Ok(())
    }
}

/// Test source that always fails.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct FailingRandom;

#[cfg(test)]
impl RandomSource for FailingRandom {
    fn fill(&mut self, _out: &mut [u8]) -> Result<(), KeyError> {
        Err(KeyError::RandomnessUnavailable)
    }
}

#[cfg(test)]
mod tests;
