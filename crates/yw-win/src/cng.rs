#![allow(unsafe_code)]
//! One-block ECB encryption/decryption with Windows CNG (spec/10 §4, §5.3): the PIV management
//! key mutual authentication of the `YubiKey` needs AES-128/192/256 or 3-key Triple DES on a
//! single 16- or 8-byte block. Uses the ECB pseudo-handles `BCRYPT_AES_ECB_ALG_HANDLE` /
//! `BCRYPT_3DES_ECB_ALG_HANDLE` (Windows 10+), so no provider is opened. No padding, no IV.
//! The key object is destroyed before returning; output buffers are the caller's to wipe.

use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_3DES_ECB_ALG_HANDLE, BCRYPT_AES_ECB_ALG_HANDLE, BCRYPT_FLAGS, BCRYPT_KEY_HANDLE,
    BCryptDecrypt, BCryptDestroyKey, BCryptEncrypt, BCryptGenerateSymmetricKey,
};

use crate::error::WinError;

/// Block cipher choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockCipher {
    /// AES with a 16-, 24- or 32-byte key, 16-byte block.
    Aes,
    /// Triple DES (EDE) with a 24-byte key, 8-byte block.
    TripleDes,
}

impl BlockCipher {
    /// Block length.
    #[must_use]
    pub const fn block_len(self) -> usize {
        match self {
            Self::Aes => 16,
            Self::TripleDes => 8,
        }
    }

    const fn key_ok(self, len: usize) -> bool {
        match self {
            Self::Aes => matches!(len, 16 | 24 | 32),
            Self::TripleDes => len == 24,
        }
    }
}

struct Key(BCRYPT_KEY_HANDLE);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: The handle came from `BCryptGenerateSymmetricKey` and is destroyed once.
        unsafe { BCryptDestroyKey(self.0) };
    }
}

#[expect(
    clippy::cast_sign_loss,
    reason = "the NTSTATUS is kept bit for bit in WinError::code"
)]
const fn failure(api: &'static str, status: i32) -> WinError {
    WinError::new(api, status as u32)
}

fn key(cipher: BlockCipher, secret: &[u8]) -> Result<Key, WinError> {
    if !cipher.key_ok(secret.len()) {
        return Err(WinError::invalid_argument("BCryptGenerateSymmetricKey"));
    }
    let algorithm = match cipher {
        BlockCipher::Aes => BCRYPT_AES_ECB_ALG_HANDLE,
        BlockCipher::TripleDes => BCRYPT_3DES_ECB_ALG_HANDLE,
    };
    let len = u32::try_from(secret.len())
        .map_err(|_| WinError::invalid_argument("BCryptGenerateSymmetricKey"))?;
    let mut handle: BCRYPT_KEY_HANDLE = core::ptr::null_mut();
    // SAFETY: A pseudo algorithm handle, a valid out pointer, a CNG-allocated key object (null,
    // 0) and `secret` readable for `len` bytes.
    let status = unsafe {
        BCryptGenerateSymmetricKey(
            algorithm,
            &raw mut handle,
            core::ptr::null_mut(),
            0,
            secret.as_ptr(),
            len,
            0,
        )
    };
    if status != 0 {
        return Err(failure("BCryptGenerateSymmetricKey", status));
    }
    Ok(Key(handle))
}

/// Encrypts (`encrypt`) or decrypts one block in ECB mode.
///
/// # Errors
///
/// An argument error for a wrong key or block length, or the CNG status.
pub fn ecb_block(
    cipher: BlockCipher,
    secret: &[u8],
    block: &[u8],
    encrypt: bool,
) -> Result<Vec<u8>, WinError> {
    let api = if encrypt {
        "BCryptEncrypt"
    } else {
        "BCryptDecrypt"
    };
    if block.len() != cipher.block_len() {
        return Err(WinError::invalid_argument(api));
    }
    let key = key(cipher, secret)?;
    let len = u32::try_from(block.len()).map_err(|_| WinError::invalid_argument(api))?;
    let mut out = vec![0_u8; block.len()];
    let mut written = 0_u32;
    let flags: BCRYPT_FLAGS = 0;
    let status = if encrypt {
        // SAFETY: `key.0` is a live key handle, `block` is readable and `out` writable for
        // `len` bytes, no padding info or IV (ECB, flags 0), `written` is a valid out pointer.
        unsafe {
            BCryptEncrypt(
                key.0,
                block.as_ptr(),
                len,
                core::ptr::null(),
                core::ptr::null_mut(),
                0,
                out.as_mut_ptr(),
                len,
                &raw mut written,
                flags,
            )
        }
    } else {
        // SAFETY: As for `BCryptEncrypt` above.
        unsafe {
            BCryptDecrypt(
                key.0,
                block.as_ptr(),
                len,
                core::ptr::null(),
                core::ptr::null_mut(),
                0,
                out.as_mut_ptr(),
                len,
                &raw mut written,
                flags,
            )
        }
    };
    if status != 0 {
        crate::mem::wipe(&mut out);
        return Err(failure(api, status));
    }
    if written != len {
        crate::mem::wipe(&mut out);
        return Err(WinError::invalid_argument(api));
    }
    Ok(out)
}

/// Verifies an ECDSA P-256 signature `r ‖ s` (64 bytes) over the SHA-256 `digest` with the
/// public key `(x, y)` (uncompressed affine coordinates, 32 bytes each), via the
/// `BCRYPT_ECDSA_P256_ALG_HANDLE` pseudo-handle (Windows 10+). Used for `WalletConnect` Verify
/// attestation JWTs (ES256, spec/13 §7). `false` for any failure.
#[must_use]
pub fn p256_verify(x: &[u8; 32], y: &[u8; 32], digest: &[u8; 32], signature: &[u8; 64]) -> bool {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALG_HANDLE, BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
        BCryptImportKeyPair, BCryptVerifySignature,
    };
    // BCRYPT_ECCKEY_BLOB { dwMagic, cbKey } ‖ X ‖ Y.
    let mut blob = Vec::with_capacity(8 + 64);
    blob.extend_from_slice(&BCRYPT_ECDSA_PUBLIC_P256_MAGIC.to_le_bytes());
    blob.extend_from_slice(&32_u32.to_le_bytes());
    blob.extend_from_slice(x);
    blob.extend_from_slice(y);
    let Ok(blob_len) = u32::try_from(blob.len()) else {
        return false;
    };
    let mut handle: BCRYPT_KEY_HANDLE = core::ptr::null_mut();
    // SAFETY: A pseudo algorithm handle, no import key, a static blob type string, a valid out
    // pointer and `blob` readable for `blob_len` bytes.
    let status = unsafe {
        BCryptImportKeyPair(
            BCRYPT_ECDSA_P256_ALG_HANDLE,
            core::ptr::null_mut(),
            BCRYPT_ECCPUBLIC_BLOB,
            &raw mut handle,
            blob.as_ptr(),
            blob_len,
            0,
        )
    };
    if status != 0 || handle.is_null() {
        return false;
    }
    let key = Key(handle);
    // SAFETY: `key.0` is a live key; the digest (32) and signature (64) are readable for the
    // lengths passed; no padding info (ECDSA).
    let status = unsafe {
        BCryptVerifySignature(
            key.0,
            core::ptr::null(),
            digest.as_ptr(),
            32,
            signature.as_ptr(),
            64,
            0,
        )
    };
    status == 0
}

#[cfg(test)]
mod tests {
    use super::{BlockCipher, ecb_block};

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(text.get(at..at + 2).unwrap(), 16).unwrap())
            .collect()
    }

    /// FIPS-197 Appendix C.1–C.3 and an SP 800-67 three-key TDEA block, both directions.
    #[test]
    fn known_answers() {
        let plain = hex("00112233445566778899aabbccddeeff");
        for (key, cipher) in [
            (
                "000102030405060708090a0b0c0d0e0f",
                "69c4e0d86a7b0430d8cdb78070b4c55a",
            ),
            (
                "000102030405060708090a0b0c0d0e0f1011121314151617",
                "dda97ca4864cdfe06eaf70a0ec0d7191",
            ),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "8ea2b7ca516745bfeafc49904b496089",
            ),
        ] {
            let key = hex(key);
            let encrypted = ecb_block(BlockCipher::Aes, &key, &plain, true).unwrap();
            assert_eq!(encrypted, hex(cipher));
            assert_eq!(
                ecb_block(BlockCipher::Aes, &key, &encrypted, false).unwrap(),
                plain
            );
        }
        let key = hex("0123456789abcdef23456789abcdef01456789abcdef0123");
        let block = hex("5468652071756663");
        let encrypted = ecb_block(BlockCipher::TripleDes, &key, &block, true).unwrap();
        assert_eq!(encrypted, hex("a826fd8ce53b855f"));
        assert_eq!(
            ecb_block(BlockCipher::TripleDes, &key, &encrypted, false).unwrap(),
            block
        );
    }

    #[test]
    fn lengths_are_checked() {
        assert!(ecb_block(BlockCipher::Aes, &[0; 15], &[0; 16], true).is_err());
        assert!(ecb_block(BlockCipher::Aes, &[0; 16], &[0; 8], true).is_err());
        assert!(ecb_block(BlockCipher::TripleDes, &[0; 16], &[0; 8], true).is_err());
        assert!(ecb_block(BlockCipher::TripleDes, &[1; 24], &[0; 16], false).is_err());
    }
}
