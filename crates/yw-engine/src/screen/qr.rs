//! The receive QR's module matrix (spec/04 §2.8): `payload` encoded with `qrcodegen` (ECC Medium),
//! as plain data every platform draws the same way (dark modules, row-major, no quiet zone; the
//! shell adds the four quiet-zone modules and picks the module size). The matrix is never cached.
//!
//! 2026-11-24 (spec/15 §4.1, §11.3, §11.4 S5-2): the encoder moved here from yw-app `ui::qr::encode`
//! (which returned the `qrcodegen` code itself); `qrcodegen 1.8.0` moved with it from yw-app's
//! dependencies to yw-engine's (spec.md D5, spec/01 §3.3), so yw-app and a later Android shell use
//! it only through this module. The module values are those of the same `qrcodegen` call (the
//! archive vector below is unchanged); the GDI layout and painting stay in yw-app `ui::qr`.

use qrcodegen::{QrCode, QrCodeEcc};

/// The fixed texts of the receive QR (spec/14). 2026-11-24 (spec/15 §11.4 S5-5): moved here
/// unchanged from yw-app `ui::qr::text` with the receive screen's builder; the GDI layout and
/// painting stay there. 2026-11-24 (S5-5 review, spec/15 §18 31 (ㄷ)): crate-private (the receive
/// screen's builder draws it; no shell code names it); yw-app's tests reach it through
/// `crate::testkit::screen::qr_text`. At S5-5 itself it was `pub` for those tests only.
pub(crate) mod text {
    yw_core::texts! {
        /// Receive-screen note: one EVM address serves every EVM chain, but the screen shows only
        /// the selected network's assets.
        RECEIVE_SHARED_ADDRESS_NOTE = "이 주소는 다른 EVM 체인(예: Ethereum·Base·Arbitrum)에서도 같은 주소이지만, 여기에는 선택한 네트워크의 자산만 보입니다. 다른 체인으로 받은 자산은 그 체인을 추가·선택해야 보입니다."
            / "This address is the same on other EVM chains (e.g. Ethereum, Base, Arbitrum), but only the selected network's assets are shown here. Assets received on another chain appear after you add and select that chain.";
    }
}

/// The modules of one QR symbol, without its quiet zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QrMatrix {
    /// Modules per side (21 for version 1 … 177 for version 40).
    size: i32,
    /// Whether each module is dark, row-major (`size × size` entries).
    dark: Vec<bool>,
}

impl QrMatrix {
    /// Modules per side.
    #[must_use]
    pub const fn size(&self) -> i32 {
        self.size
    }

    /// Whether the module at column `x`, row `y` is dark; `false` outside the symbol (as
    /// `qrcodegen::QrCode::get_module`).
    #[must_use]
    pub fn module(&self, x: i32, y: i32) -> bool {
        if !(0..self.size).contains(&x) || !(0..self.size).contains(&y) {
            return false;
        }
        let index = i64::from(y)
            .saturating_mul(i64::from(self.size))
            .saturating_add(i64::from(x));
        usize::try_from(index)
            .ok()
            .and_then(|index| self.dark.get(index))
            .copied()
            .unwrap_or(false)
    }
}

/// Encodes `payload` (ECC Medium); `None` when it does not fit a version-40 symbol.
#[must_use]
pub fn encode(payload: &str) -> Option<QrMatrix> {
    let code = QrCode::encode_text(payload, QrCodeEcc::Medium).ok()?;
    let size = code.size();
    let mut dark = Vec::with_capacity(usize::try_from(size.saturating_mul(size)).unwrap_or(0));
    for y in 0..size {
        for x in 0..size {
            dark.push(code.get_module(x, y));
        }
    }
    Some(QrMatrix { size, dark })
}

#[cfg(test)]
mod tests {
    use super::{QrMatrix, encode};
    use crate::screen::{EvmQrKind, evm_payload, evm_receive_payload};
    use qrcodegen::{QrCode, QrCodeEcc};
    use yw_core::evm::address::parse_address;

    /// The archive matrix digest: SHA-256 of `size` (i32 BE) and one byte per module, row-major.
    fn matrix_digest(code: &QrMatrix) -> [u8; 32] {
        let mut bytes = code.size().to_be_bytes().to_vec();
        for y in 0..code.size() {
            for x in 0..code.size() {
                bytes.push(u8::from(code.module(x, y)));
            }
        }
        yw_core::codec::sha256(&bytes)
    }

    /// Moved from yw-app `ui::qr` (2026-11-24, S5-2) with the encoder: the same archive vector.
    #[test]
    fn eip681_payload_and_matrix_match_the_archive_vector() {
        let address = parse_address("0x52908400098527886E0F7030069857D2E4169EE7").unwrap();
        let payload = evm_payload(&address, 11_155_111);
        assert_eq!(
            payload,
            "ethereum:0x52908400098527886E0F7030069857D2E4169EE7@11155111"
        );
        let code = encode(&payload).unwrap();
        assert_eq!(code.size(), 33);
        // archive receive_qr.rs eip681_payload_and_checksum_validation_are_exact
        assert_eq!(
            matrix_digest(&code),
            [
                131, 144, 58, 38, 34, 196, 128, 134, 250, 160, 95, 232, 117, 222, 8, 181, 233, 169,
                173, 246, 52, 218, 210, 55, 92, 71, 101, 33, 138, 202, 30, 161,
            ]
        );
        // The payload is parameterised by the chain id.
        let other = evm_payload(&address, 84_532);
        assert!(other.ends_with("@84532"));
    }

    /// The matrix is the `qrcodegen` code's modules, one for one, and reads `false` outside it
    /// (as `get_module`, which yw-app's BMP fixture relies on for the quiet zone).
    #[test]
    fn the_matrix_is_the_codes_modules() {
        let address = parse_address("0x52908400098527886E0F7030069857D2E4169EE7").unwrap();
        for payload in [
            String::new(),
            evm_receive_payload(&address, 1, EvmQrKind::PlainAddress),
            evm_receive_payload(&address, 1, EvmQrKind::Eip681),
            "x".repeat(700),
        ] {
            let code = QrCode::encode_text(&payload, QrCodeEcc::Medium).unwrap();
            let matrix = encode(&payload).unwrap();
            assert_eq!(matrix.size(), code.size());
            for y in -5..code.size() + 5 {
                for x in -5..code.size() + 5 {
                    assert_eq!(matrix.module(x, y), code.get_module(x, y), "{x},{y}");
                }
            }
        }
        // Too long for a version-40 symbol at ECC Medium.
        assert!(encode(&"x".repeat(3_000)).is_none());
    }
}
