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
//!
//! 2026-11-24 (spec/15 §4.1, §11.4 S5-2): the encoding moved to `yw_engine::screen::qr::encode`
//! (the module matrix `QrMatrix`, the same `qrcodegen` call), with `qrcodegen` itself; this module
//! keeps the Windows layout and the GDI painting of that matrix. yw-app no longer depends on
//! `qrcodegen` directly (`scripts/check-core-deps.mjs`). The decoder round trips that used the
//! encoder moved to yw-engine `walletconnect::qr_round_trip`, the archive vector to
//! `yw_engine::screen::qr`.
//!
//! 2026-11-24 (spec/15 §11.4 S5-5): the receive note `RECEIVE_SHARED_ADDRESS_NOTE` (catalogue
//! `text`) moved to `yw_engine::screen::qr::text` with the receive screen's builder.

use yw_engine::screen::qr::QrMatrix;
use yw_win::ui::{Color, PaintDc, Rect};

/// Quiet zone in modules.
pub const QUIET_ZONE_MODULES: i32 = 4;
/// Smallest module in pixels.
pub const MIN_MODULE_PIXELS: i32 = 6;
/// QR dark color.
pub const QR_DARK: Color = Color(0x0000_0000);
/// QR light color.
pub const QR_LIGHT: Color = Color(0x00FF_FFFF);

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
pub fn paint(dc: &mut PaintDc<'_>, x: i32, y: i32, code: &QrMatrix, layout: &QrLayout) {
    let side = layout.canvas_pixels();
    dc.fill_rect(Rect::new(x, y, side, side), QR_LIGHT);
    let module = layout.module_pixels;
    for row in 0..layout.symbol_modules {
        for column in 0..layout.symbol_modules {
            if code.module(column, row) {
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
    use super::{layout, preferred_module};
    use yw_core::evm::address::parse_address;
    use yw_core::lang::Lang;
    use yw_engine::screen::qr::encode;
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

    #[test]
    fn english_labels_have_no_hangul() {
        use yw_core::lang::has_hangul;
        for kind in [EvmQrKind::Eip681, EvmQrKind::PlainAddress] {
            assert!(!has_hangul(kind.label(Lang::En)));
            assert!(!kind.label(Lang::Ko).is_empty());
        }
        assert!(!has_hangul(
            yw_engine::screen::qr::text::RECEIVE_SHARED_ADDRESS_NOTE.get(Lang::En)
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
