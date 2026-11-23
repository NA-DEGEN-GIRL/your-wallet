//! Receive QR (spec/04 §2.8): EIP-681 `ethereum:<EIP-55 address>@<chainId>` (or, by
//! `EvmQrKind::PlainAddress`, the bare EIP-55 address for exchange apps) encoded with
//! `qrcodegen` (ECC Medium) and painted with GDI rectangles, four quiet-zone modules, integer
//! modules of `max(6, round(8 × dpi / 96))` pixels (down to 6 when the space is short). The matrix
//! is never cached. Ported from `archive/spec-v2.4:demo/sepolia-wallet/src/receive_qr.rs:1-262`
//! (layout rules `:51-130`, payload `:132-139` with the chain id as a parameter, egui drawing
//! `:170-221` replaced by `PaintDc::fill_rect`).
//!
//! 2026-11-22 (spec/15 §11.4 S4d E0a): the choice `EvmQrKind`, its labels and the payloads
//! (`evm_payload`, `evm_receive_payload`) moved to `yw_engine::screen` unchanged (the wallet's
//! EVM state holds the choice); the encoding and painting stay here.

use qrcodegen::{QrCode, QrCodeEcc};
use yw_win::ui::{Color, PaintDc, Rect};

/// Quiet zone in modules.
pub const QUIET_ZONE_MODULES: i32 = 4;
/// Smallest module in pixels.
pub const MIN_MODULE_PIXELS: i32 = 6;
/// QR dark color.
pub const QR_DARK: Color = Color(0x0000_0000);
/// QR light color.
pub const QR_LIGHT: Color = Color(0x00FF_FFFF);

/// The fixed texts of the receive QR (spec/14).
pub mod text {
    yw_core::texts! {
        /// Receive-screen note: one EVM address serves every EVM chain, but the screen shows only
        /// the selected network's assets.
        RECEIVE_SHARED_ADDRESS_NOTE = "이 주소는 다른 EVM 체인(예: Ethereum·Base·Arbitrum)에서도 같은 주소이지만, 여기에는 선택한 네트워크의 자산만 보입니다. 다른 체인으로 받은 자산은 그 체인을 추가·선택해야 보입니다."
            / "This address is the same on other EVM chains (e.g. Ethereum, Base, Arbitrum), but only the selected network's assets are shown here. Assets received on another chain appear after you add and select that chain.";
    }
}

pub use text::RECEIVE_SHARED_ADDRESS_NOTE;

/// Encodes `payload` (ECC Medium).
#[must_use]
pub fn encode(payload: &str) -> Option<QrCode> {
    QrCode::encode_text(payload, QrCodeEcc::Medium).ok()
}

/// Integer-pixel geometry of one QR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QrLayout {
    /// Symbol modules per side.
    pub symbol_modules: i32,
    /// Modules per side with the quiet zone.
    pub total_modules: i32,
    /// Pixels per module.
    pub module_pixels: i32,
}

impl QrLayout {
    /// Canvas side in pixels.
    #[must_use]
    pub const fn canvas_pixels(&self) -> i32 {
        self.total_modules.saturating_mul(self.module_pixels)
    }
}

/// The preferred module size: `max(6, round(8 × dpi / 96))`.
#[must_use]
pub fn preferred_module(dpi: u32) -> i32 {
    let scaled = (u64::from(dpi) * 8 + 48) / 96;
    i32::try_from(scaled)
        .unwrap_or(i32::MAX)
        .max(MIN_MODULE_PIXELS)
}

/// The layout for `available` pixels per side; `None` when even 6-pixel modules do not fit
/// ("창을 넓히면 QR이 표시됩니다").
#[must_use]
pub fn layout(symbol_modules: i32, dpi: u32, available: i32) -> Option<QrLayout> {
    if !(21..=177).contains(&symbol_modules) {
        return None;
    }
    let total = symbol_modules.checked_add(QUIET_ZONE_MODULES.checked_mul(2)?)?;
    let fit = available.checked_div(total)?;
    let module = preferred_module(dpi).min(fit);
    (module >= MIN_MODULE_PIXELS).then_some(QrLayout {
        symbol_modules,
        total_modules: total,
        module_pixels: module,
    })
}

/// Paints the QR with its quiet zone at `(x, y)`.
pub fn paint(dc: &mut PaintDc<'_>, x: i32, y: i32, code: &QrCode, layout: &QrLayout) {
    let side = layout.canvas_pixels();
    dc.fill_rect(Rect::new(x, y, side, side), QR_LIGHT);
    let module = layout.module_pixels;
    for row in 0..layout.symbol_modules {
        for column in 0..layout.symbol_modules {
            if code.get_module(column, row) {
                let left = x.saturating_add(
                    column
                        .saturating_add(QUIET_ZONE_MODULES)
                        .saturating_mul(module),
                );
                let top = y.saturating_add(
                    row.saturating_add(QUIET_ZONE_MODULES)
                        .saturating_mul(module),
                );
                dc.fill_rect(Rect::new(left, top, module, module), QR_DARK);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{encode, layout, preferred_module};
    use yw_core::evm::address::parse_address;
    use yw_core::lang::Lang;
    use yw_engine::screen::{EvmQrKind, evm_payload, evm_receive_payload};

    #[test]
    fn plain_address_payload_is_the_bare_eip55_address() {
        let address = parse_address("0x52908400098527886E0F7030069857D2E4169EE7").unwrap();
        assert_eq!(EvmQrKind::default(), EvmQrKind::Eip681);
        assert_eq!(
            evm_receive_payload(&address, 1, EvmQrKind::Eip681),
            evm_payload(&address, 1)
        );
        let plain = evm_receive_payload(&address, 1, EvmQrKind::PlainAddress);
        assert_eq!(plain, "0x52908400098527886E0F7030069857D2E4169EE7");
        // Same address on every chain: the plain payload does not depend on the chain id.
        assert_eq!(
            evm_receive_payload(&address, 84_532, EvmQrKind::PlainAddress),
            plain
        );
        let code = encode(&plain).unwrap();
        assert!(code.size() >= 21);
        assert_ne!(
            EvmQrKind::Eip681.label(Lang::Ko),
            EvmQrKind::PlainAddress.label(Lang::Ko)
        );
    }

    /// The archive matrix digest: SHA-256 of `size` (i32 BE) and one byte per module, row-major.
    fn matrix_digest(code: &qrcodegen::QrCode) -> [u8; 32] {
        let mut bytes = code.size().to_be_bytes().to_vec();
        for y in 0..code.size() {
            for x in 0..code.size() {
                bytes.push(u8::from(code.get_module(x, y)));
            }
        }
        yw_core::codec::sha256(&bytes)
    }

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

    #[test]
    fn english_labels_have_no_hangul() {
        use yw_core::lang::has_hangul;
        for kind in [EvmQrKind::Eip681, EvmQrKind::PlainAddress] {
            assert!(!has_hangul(kind.label(Lang::En)));
            assert!(!kind.label(Lang::Ko).is_empty());
        }
        assert!(!has_hangul(
            super::RECEIVE_SHARED_ADDRESS_NOTE.get(Lang::En)
        ));
        assert_eq!(
            EvmQrKind::Eip681.label(Lang::Ko),
            "지갑 앱용 QR (네트워크 포함)"
        );
    }

    #[test]
    fn layout_uses_integer_modules_and_a_six_pixel_floor() {
        assert_eq!(preferred_module(96), 8);
        assert_eq!(preferred_module(144), 12);
        assert_eq!(preferred_module(60), 6);
        let roomy = layout(33, 96, 1_000).unwrap();
        assert_eq!((roomy.total_modules, roomy.module_pixels), (41, 8));
        assert_eq!(roomy.canvas_pixels(), 328);
        let tight = layout(33, 144, 300).unwrap();
        assert_eq!(tight.module_pixels, 7);
        assert_eq!(layout(33, 96, 246).map(|l| l.module_pixels), Some(6));
        assert_eq!(layout(33, 96, 245), None);
        assert_eq!(layout(20, 96, 1_000), None);
    }
}

/// Round trips through the `WalletConnect` QR reader (`walletconnect::qr_decode`): codes made by
/// this app's encoder (`qrcodegen`), drawn like screenshots. 2026-11-17 S2: moved from
/// `walletconnect/tests.rs`, so the decoder's tests do not need `qrcodegen` (which stays with the
/// Windows UI until the screen model moves, spec/15 §11.4 S5).
#[cfg(test)]
mod decode_round_trip {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        clippy::cast_possible_wrap
    )]

    use qrcodegen::{QrCode, QrCodeEcc};

    use yw_engine::walletconnect::qr_decode::{Gray, decode, decode_bgra_text};

    const URI: &str = "wc:9e5b70f5ddde5d6f3f5a7b9b4a0a3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b@2?expiryTimestamp=1762430000&relay-protocol=irn&symKey=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&methods=wc_sessionPropose,wc_sessionAuthenticate";

    struct Scene {
        width: usize,
        height: usize,
        /// Module size in pixels.
        module: f64,
        /// Rotation in degrees.
        angle: f64,
        /// Code centre.
        center: (f64, f64),
        dark: u8,
        light: u8,
        background: u8,
    }

    fn matrix(qr: &QrCode) -> (usize, Vec<bool>) {
        let size = qr.size();
        let mut out = Vec::new();
        for y in 0..size {
            for x in 0..size {
                out.push(qr.get_module(x, y));
            }
        }
        (size as usize, out)
    }

    /// Renders the matrix with a 4-module quiet zone, rotated and scaled, 3×3 supersampled, on a
    /// "screenshot" background with a few dark UI boxes away from the code.
    fn render(size: usize, modules: &[bool], scene: &Scene) -> Vec<u8> {
        let total = size as f64 + 8.0;
        let (sin, cos) = scene.angle.to_radians().sin_cos();
        let mut pixels = Vec::with_capacity(scene.width * scene.height * 4);
        let mut seed = 0x1234_5678_u32;
        let mut boxes = Vec::new();
        for _ in 0..6 {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            let x = (seed >> 8) as usize % scene.width;
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            let y = (seed >> 8) as usize % scene.height;
            boxes.push((x, y));
        }
        let half = total * scene.module / 2.0;
        for py in 0..scene.height {
            for px in 0..scene.width {
                let mut sum = 0.0;
                let mut inside_any = false;
                for sy in 0..3 {
                    for sx in 0..3 {
                        let fx = px as f64 + (f64::from(sx) + 0.5) / 3.0 - scene.center.0;
                        let fy = py as f64 + (f64::from(sy) + 0.5) / 3.0 - scene.center.1;
                        // Inverse rotation into the code frame.
                        let rx = fx * cos + fy * sin;
                        let ry = -fx * sin + fy * cos;
                        let mx = (rx + half) / scene.module - 4.0;
                        let my = (ry + half) / scene.module - 4.0;
                        let inside_quiet = (rx + half) >= 0.0
                            && (ry + half) >= 0.0
                            && (rx + half) < total * scene.module
                            && (ry + half) < total * scene.module;
                        inside_any |= inside_quiet;
                        let value = if !inside_quiet {
                            let near_box = boxes
                                .iter()
                                .any(|(bx, by)| px.abs_diff(*bx) < 18 && py.abs_diff(*by) < 10);
                            if near_box {
                                40.0
                            } else {
                                f64::from(scene.background)
                            }
                        } else if mx >= 0.0
                            && my >= 0.0
                            && (mx as usize) < size
                            && (my as usize) < size
                            && modules[my as usize * size + mx as usize]
                        {
                            f64::from(scene.dark)
                        } else {
                            f64::from(scene.light)
                        };
                        sum += value;
                    }
                }
                let _ = inside_any;
                let value = (sum / 9.0).round().clamp(0.0, 255.0) as u8;
                pixels.extend_from_slice(&[value, value, value, 255]);
            }
        }
        pixels
    }

    fn scene(width: usize, height: usize, module: f64, angle: f64) -> Scene {
        Scene {
            width,
            height,
            module,
            angle,
            center: (width as f64 / 2.0, height as f64 / 2.0),
            dark: 20,
            light: 250,
            background: 230,
        }
    }

    fn decode_scene(qr: &QrCode, scene: &Scene) -> Option<String> {
        let (size, modules) = matrix(qr);
        let pixels = render(size, &modules, scene);
        // 2026-11-21 (S4 F15): the decoder returns a wiped `Zeroizing<String>`; tests compare a copy.
        decode_bgra_text(scene.width, scene.height, &pixels).map(|text| text.as_str().to_owned())
    }

    /// Codes made by the app's own encoder (`qrcodegen`), several versions and levels, upright.
    #[test]
    fn qr_decodes_generated_codes() {
        let long = format!("{URI}&relay-data=");
        for (text, ecc) in [
            (URI, QrCodeEcc::Medium),
            (URI, QrCodeEcc::Low),
            (URI, QrCodeEcc::High),
            (long.as_str(), QrCodeEcc::Quartile),
            ("HELLO WORLD 123", QrCodeEcc::Medium),
            ("31415926535897932384626433", QrCodeEcc::Low),
        ] {
            let qr = QrCode::encode_text(text, ecc).unwrap();
            let module = 4.0;
            let side = ((f64::from(qr.size()) + 8.0) * module) as usize + 40;
            let found = decode_scene(&qr, &scene(side, side, module, 0.0));
            assert_eq!(
                found.as_deref(),
                Some(text),
                "version {}",
                qr.version().value()
            );
        }
    }

    /// Screenshot-like samples: rotated and non-integer scaled codes inside a larger image with UI
    /// boxes, a 90° turn, a light-on-dark code, and a high-version code.
    #[test]
    fn qr_decodes_rotated_scaled_and_inverted_screenshots() {
        let qr = QrCode::encode_text(URI, QrCodeEcc::Medium).unwrap();
        for (module, angle) in [
            (3.3, 17.0),
            (2.6, -8.0),
            (5.1, 90.0),
            (3.0, 180.0),
            (4.4, 33.0),
        ] {
            let found = decode_scene(&qr, &scene(900, 700, module, angle));
            assert_eq!(
                found.as_deref(),
                Some(URI),
                "module {module}, angle {angle}"
            );
        }
        let mut dark_mode = scene(700, 600, 3.5, 5.0);
        dark_mode.dark = 245;
        dark_mode.light = 25;
        dark_mode.background = 30;
        assert_eq!(decode_scene(&qr, &dark_mode).as_deref(), Some(URI));
        let big = "x".repeat(700);
        let qr = QrCode::encode_text(&big, QrCodeEcc::Medium).unwrap();
        assert!(qr.version().value() >= 15);
        let found = decode_scene(&qr, &scene(1_000, 1_000, 6.0, 4.0));
        assert_eq!(found.as_deref(), Some(big.as_str()));
    }

    /// Reed–Solomon corrects damaged modules (a smudge over part of the data area).
    #[test]
    fn qr_corrects_damaged_modules() {
        let qr = QrCode::encode_text(URI, QrCodeEcc::Medium).unwrap();
        let (size, mut modules) = matrix(&qr);
        for y in 22..26 {
            for x in 20..26 {
                modules[y * size + x] = !modules[y * size + x];
            }
        }
        let scene = scene(500, 500, 4.0, 0.0);
        let pixels = render(size, &modules, &scene);
        assert_eq!(
            decode_bgra_text(scene.width, scene.height, &pixels)
                .as_deref()
                .map(String::as_str),
            Some(URI)
        );
        // No code at all.
        let blank = Gray::new(64, 64, vec![255; 64 * 64]).unwrap();
        assert!(decode(&blank).is_none());
    }
}
