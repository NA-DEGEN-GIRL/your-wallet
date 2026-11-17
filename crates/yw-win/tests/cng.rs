//! CNG P-256 ECDSA on the development PC (spec/13 §7): the ES256 example of RFC 7515
//! Appendix A.3 verifies with `cng::p256_verify`, the check the `WalletConnect` Verify v3
//! attestations use; a flipped bit, another digest or another key does not.
//!
//! 2026-11-17 S2: moved from yw-app `walletconnect/tests.rs`
//! (`es256_rfc7515_vector_verifies_with_cng`) when the Verify code stopped calling CNG directly. The values are the RFC's, decoded from
//! base64url; the digest is SHA-256 of the RFC's `header.payload` text.

use yw_win::cng::p256_verify;

/// RFC 7515 A.3 key `x` (`f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU`).
const X: &str = "7fcdce2770f6c45d4183cbee6fdb4b7b580733357be9ef13bacf6e3c7bd15445";
/// RFC 7515 A.3 key `y` (`x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0`).
const Y: &str = "c7f144cd1bbd9b7e872cdfedb9eeb9f4b3695d6ea90b24ad8a4623288588e5ad";
/// SHA-256 of the RFC's JWS signing input.
const DIGEST: &str = "21c67368f436577f447f805162ca13b80d046a3fe467247e65ea477aa750fa2e";
/// The RFC's signature `r ‖ s`.
const SIGNATURE: &str = "0ed1215379636c483c2f7f155807d402a3b228033af97c7e17819ac3169ea665\
                         c50a07d38c3c70e5d8f12daf084a5480a66590c5f293509a8f3f7f8a83a354d5";

fn bytes<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let digits: Vec<u8> = hex
        .bytes()
        .filter(u8::is_ascii_hexdigit)
        .map(|digit| match digit {
            b'0'..=b'9' => digit - b'0',
            _ => digit.to_ascii_lowercase() - b'a' + 10,
        })
        .collect();
    let pairs: Vec<u8> = digits
        .chunks(2)
        .map(|pair| (pair[0] << 4) | pair[1])
        .collect();
    <[u8; N]>::try_from(pairs.as_slice()).ok()
}

#[test]
fn es256_rfc7515_vector_verifies_with_cng() {
    let (x, y) = (bytes::<32>(X).unwrap(), bytes::<32>(Y).unwrap());
    let digest = bytes::<32>(DIGEST).unwrap();
    let signature = bytes::<64>(SIGNATURE).unwrap();
    assert!(p256_verify(&x, &y, &digest, &signature));
    let mut bad = signature;
    bad[10] ^= 1;
    assert!(!p256_verify(&x, &y, &digest, &bad));
    let mut other_digest = digest;
    other_digest[0] ^= 1;
    assert!(!p256_verify(&x, &y, &other_digest, &signature));
    // `y` of another point: not on the curve with this `x`, or another key; either way, no.
    let mut other_y = y;
    other_y[31] ^= 1;
    assert!(!p256_verify(&x, &other_y, &digest, &signature));
}
