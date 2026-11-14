//! Receive QR (spec/04 §2.8): EIP-681 `ethereum:<EIP-55 address>@<chainId>` (or, by
//! [`EvmQrKind::PlainAddress`], the bare EIP-55 address for exchange apps) encoded with
//! `qrcodegen` (ECC Medium) and painted with GDI rectangles, four quiet-zone modules, integer
//! modules of `max(6, round(8 × dpi / 96))` pixels (down to 6 when the space is short). The matrix
//! is never cached. Ported from `archive/spec-v2.4:demo/sepolia-wallet/src/receive_qr.rs:1-262`
//! (layout rules `:51-130`, payload `:132-139` with the chain id as a parameter, egui drawing
//! `:170-221` replaced by `PaintDc::fill_rect`).

use qrcodegen::{QrCode, QrCodeEcc};
use yw_core::evm::address::Address;
use yw_core::lang::Lang;
use yw_win::ui::{Color, PaintDc, Rect};

/// Quiet zone in modules.
pub const QUIET_ZONE_MODULES: i32 = 4;
/// Smallest module in pixels.
pub const MIN_MODULE_PIXELS: i32 = 6;
/// QR dark color.
pub const QR_DARK: Color = Color(0x0000_0000);
/// QR light color.
pub const QR_LIGHT: Color = Color(0x00FF_FFFF);

/// What the EVM receive QR encodes (spec/04 §2.8).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EvmQrKind {
    /// EIP-681 `ethereum:<EIP-55 address>@<chainId>` (default; wallets pick the network).
    #[default]
    Eip681,
    /// The bare EIP-55 address, for exchange apps that reject `ethereum:` URIs.
    PlainAddress,
}

impl EvmQrKind {
    /// The choice label for the receive screen.
    #[must_use]
    pub const fn label(self, lang: Lang) -> &'static str {
        match self {
            Self::Eip681 => text::QR_WALLET_APP.get(lang),
            Self::PlainAddress => text::QR_ADDRESS_ONLY.get(lang),
        }
    }
}

/// The fixed texts of the receive QR (spec/14).
pub mod text {
    yw_core::texts! {
        /// The EIP-681 choice.
        QR_WALLET_APP = "지갑 앱용 QR (네트워크 포함)" / "QR for wallet apps (with network)";
        /// The bare-address choice.
        QR_ADDRESS_ONLY = "주소만 QR (거래소 앱용)" / "Address-only QR (for exchange apps)";
        /// Receive-screen note: one EVM address serves every EVM chain, but the screen shows only
        /// the selected network's assets.
        RECEIVE_SHARED_ADDRESS_NOTE = "이 주소는 다른 EVM 체인(예: Ethereum·Base·Arbitrum)에서도 같은 주소이지만, 여기에는 선택한 네트워크의 자산만 보입니다. 다른 체인으로 받은 자산은 그 체인을 추가·선택해야 보입니다."
            / "This address is the same on other EVM chains (e.g. Ethereum, Base, Arbitrum), but only the selected network's assets are shown here. Assets received on another chain appear after you add and select that chain.";
    }
}

pub use text::RECEIVE_SHARED_ADDRESS_NOTE;

/// The EVM receive payload (EIP-681).
#[must_use]
pub fn evm_payload(address: &Address, chain_id: u64) -> String {
    format!("ethereum:{}@{chain_id}", address.to_checksum())
}

/// The EVM receive payload of `kind`: EIP-681 or the bare EIP-55 address.
#[must_use]
pub fn evm_receive_payload(address: &Address, chain_id: u64, kind: EvmQrKind) -> String {
    match kind {
        EvmQrKind::Eip681 => evm_payload(address, chain_id),
        EvmQrKind::PlainAddress => address.to_checksum(),
    }
}

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
    use super::{EvmQrKind, encode, evm_payload, evm_receive_payload, layout, preferred_module};
    use yw_core::evm::address::parse_address;
    use yw_core::lang::Lang;

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
