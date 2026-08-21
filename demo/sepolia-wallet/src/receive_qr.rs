//! Offline EIP-681 receive QR generation and immediate-mode rendering.
//!
//! The encoded address is identifying public metadata. This module deliberately
//! keeps no cache or texture: the QR matrix and URI live only for the frame in
//! which the user explicitly reveals them.

use eframe::egui;
use qrcodegen::{QrCode, QrCodeEcc};
use sha3::{Digest as _, Keccak256};
use zeroize::Zeroizing;

use crate::rpc::SEPOLIA_CHAIN_ID;

const ADDRESS_HEX_BYTES: usize = 40;
const QUIET_ZONE_MODULES: u32 = 4;
const PREFERRED_MODULE_POINTS: f32 = 8.0;
const MIN_MODULE_PIXELS: u32 = 6;
const ALIGNMENT_SLACK_PIXELS: u32 = 1;
pub(crate) const MAX_ETH_AMOUNT_INPUT_BYTES: usize = 79;
const ETH_DECIMALS: u8 = 18;

/// A category-only receive-QR failure that never contains an address or URI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReceiveQrError {
    InvalidAddress,
    InvalidAmount,
    Encoding,
    InvalidLayout,
}

/// One frame-local QR bound to a backend-validated checksummed address.
///
/// Deliberately does not implement `Debug`: both the URI and matrix identify
/// the wallet account.
pub(crate) struct ReceiveQr {
    payment_uri: Zeroizing<String>,
    code: QrCode,
}

/// Non-identifying evidence about the painted QR geometry.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct PaintMetrics {
    pub(crate) symbol_modules: u32,
    pub(crate) total_modules: u32,
    pub(crate) module_pixels: u32,
    pub(crate) dark_modules: usize,
    pub(crate) canvas: egui::Rect,
    pub(crate) clip_rect: egui::Rect,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct QrLayout {
    symbol_modules: u32,
    total_modules: u32,
    module_pixels: u32,
    pixels_per_point: f32,
}

impl QrLayout {
    fn new(
        symbol_modules: i32,
        pixels_per_point: f32,
        available_points: f32,
    ) -> Result<Self, ReceiveQrError> {
        let symbol_modules = u32::try_from(symbol_modules)
            .ok()
            .filter(|modules| (21..=177).contains(modules))
            .ok_or(ReceiveQrError::InvalidLayout)?;
        if !pixels_per_point.is_finite()
            || pixels_per_point <= 0.0
            || !available_points.is_finite()
            || available_points <= 0.0
        {
            return Err(ReceiveQrError::InvalidLayout);
        }

        let preferred_module_pixels = (PREFERRED_MODULE_POINTS * pixels_per_point).ceil();
        let available_pixels = (available_points * pixels_per_point).floor();
        if !preferred_module_pixels.is_finite()
            || !available_pixels.is_finite()
            || !(1.0..=(u32::MAX as f32)).contains(&preferred_module_pixels)
            || !(1.0..=(u32::MAX as f32)).contains(&available_pixels)
        {
            return Err(ReceiveQrError::InvalidLayout);
        }
        let total_modules = symbol_modules
            .checked_add(QUIET_ZONE_MODULES * 2)
            .ok_or(ReceiveQrError::InvalidLayout)?;
        let available_pixels = available_pixels as u32;
        let available_for_modules = available_pixels
            .checked_sub(ALIGNMENT_SLACK_PIXELS)
            .ok_or(ReceiveQrError::InvalidLayout)?;
        let maximum_module_pixels = available_for_modules / total_modules;
        if maximum_module_pixels < MIN_MODULE_PIXELS {
            return Err(ReceiveQrError::InvalidLayout);
        }
        let preferred_module_pixels = (preferred_module_pixels as u32).max(MIN_MODULE_PIXELS);
        let module_pixels = preferred_module_pixels.min(maximum_module_pixels);
        let canvas_pixels = total_modules
            .checked_mul(module_pixels)
            .ok_or(ReceiveQrError::InvalidLayout)?;
        canvas_pixels
            .checked_add(ALIGNMENT_SLACK_PIXELS)
            .filter(|required| *required <= available_pixels)
            .ok_or(ReceiveQrError::InvalidLayout)?;

        Ok(Self {
            symbol_modules,
            total_modules,
            module_pixels,
            pixels_per_point,
        })
    }

    fn canvas_pixels(self) -> u32 {
        self.total_modules * self.module_pixels
    }

    fn canvas_points(self) -> f32 {
        self.canvas_pixels() as f32 / self.pixels_per_point
    }

    fn allocation_points(self) -> f32 {
        (self.canvas_pixels() + ALIGNMENT_SLACK_PIXELS) as f32 / self.pixels_per_point
    }

    fn point_at_module(self, origin_pixels: f32, module: u32) -> f32 {
        (origin_pixels + (module * self.module_pixels) as f32) / self.pixels_per_point
    }
}

impl ReceiveQr {
    pub(crate) fn new(address: &str) -> Result<Self, ReceiveQrError> {
        if !is_exact_eip55_address(address) {
            return Err(ReceiveQrError::InvalidAddress);
        }
        let payment_uri = Zeroizing::new(format!("ethereum:{address}@{SEPOLIA_CHAIN_ID}"));
        Self::encode(payment_uri)
    }

    pub(crate) fn new_with_native_eth_amount(
        address: &str,
        amount_eth: &str,
    ) -> Result<Self, ReceiveQrError> {
        if !is_exact_eip55_address(address) {
            return Err(ReceiveQrError::InvalidAddress);
        }
        let value_wei = canonical_wei(amount_eth)?;
        let payment_uri = Zeroizing::new(format!(
            "ethereum:{address}@{SEPOLIA_CHAIN_ID}?value={}",
            value_wei.as_str()
        ));
        Self::encode(payment_uri)
    }

    fn encode(payment_uri: Zeroizing<String>) -> Result<Self, ReceiveQrError> {
        let code = QrCode::encode_text(payment_uri.as_str(), QrCodeEcc::Medium)
            .map_err(|_| ReceiveQrError::Encoding)?;
        Ok(Self { payment_uri, code })
    }

    pub(crate) fn payment_uri(&self) -> &str {
        self.payment_uri.as_str()
    }

    /// Paint fixed black modules on a white four-module quiet zone.
    ///
    /// Every boundary is rounded in physical-pixel space. No image, texture,
    /// filesystem, clipboard, or network API is used here.
    pub(crate) fn paint(&self, ui: &mut egui::Ui) -> Result<PaintMetrics, ReceiveQrError> {
        let pixels_per_point = ui.ctx().pixels_per_point();
        let clip_rect = ui.clip_rect();
        let visible_rect = ui.available_rect_before_wrap().intersect(clip_rect);
        let available_side = visible_rect.width().min(visible_rect.height());
        let layout = QrLayout::new(self.code.size(), pixels_per_point, available_side)?;
        let desired_size = egui::Vec2::splat(layout.canvas_points());
        let allocation_size = egui::Vec2::splat(layout.allocation_points());
        let (allocated, _) = ui.allocate_exact_size(allocation_size, egui::Sense::hover());
        let origin_x_pixels = (allocated.min.x * pixels_per_point).ceil();
        let origin_y_pixels = (allocated.min.y * pixels_per_point).ceil();
        let canvas_min = egui::pos2(
            origin_x_pixels / pixels_per_point,
            origin_y_pixels / pixels_per_point,
        );
        let canvas = egui::Rect::from_min_size(canvas_min, desired_size);
        if !clip_rect.contains(canvas.min) || !clip_rect.contains(canvas.max) {
            return Err(ReceiveQrError::InvalidLayout);
        }
        ui.painter().rect_filled(canvas, 0.0, egui::Color32::WHITE);

        let mut dark_modules = 0_usize;
        for y in 0..layout.symbol_modules {
            for x in 0..layout.symbol_modules {
                let x_i32 = i32::try_from(x).map_err(|_| ReceiveQrError::InvalidLayout)?;
                let y_i32 = i32::try_from(y).map_err(|_| ReceiveQrError::InvalidLayout)?;
                if !self.code.get_module(x_i32, y_i32) {
                    continue;
                }
                dark_modules += 1;
                let left = layout.point_at_module(origin_x_pixels, x + QUIET_ZONE_MODULES);
                let top = layout.point_at_module(origin_y_pixels, y + QUIET_ZONE_MODULES);
                let right = layout.point_at_module(origin_x_pixels, x + QUIET_ZONE_MODULES + 1);
                let bottom = layout.point_at_module(origin_y_pixels, y + QUIET_ZONE_MODULES + 1);
                ui.painter().rect_filled(
                    egui::Rect::from_min_max(egui::pos2(left, top), egui::pos2(right, bottom)),
                    0.0,
                    egui::Color32::BLACK,
                );
            }
        }

        Ok(PaintMetrics {
            symbol_modules: layout.symbol_modules,
            total_modules: layout.total_modules,
            module_pixels: layout.module_pixels,
            dark_modules,
            canvas,
            clip_rect,
        })
    }
}

fn canonical_wei(amount_eth: &str) -> Result<Zeroizing<String>, ReceiveQrError> {
    if amount_eth.len() > MAX_ETH_AMOUNT_INPUT_BYTES {
        return Err(ReceiveQrError::InvalidAmount);
    }
    let amount = crate::erc20::parse_token_amount(amount_eth, ETH_DECIMALS)
        .map_err(|_| ReceiveQrError::InvalidAmount)?;
    crate::erc20::format_token_amount(amount, 0)
        .map(Zeroizing::new)
        .map_err(|_| ReceiveQrError::InvalidAmount)
}

fn is_exact_eip55_address(address: &str) -> bool {
    let Some(hex) = address.strip_prefix("0x") else {
        return false;
    };
    if hex.len() != ADDRESS_HEX_BYTES
        || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        || hex.bytes().all(|byte| byte == b'0')
    {
        return false;
    }

    let lowercase = hex.to_ascii_lowercase();
    let hash = Keccak256::digest(lowercase.as_bytes());
    hex.bytes().enumerate().all(|(index, byte)| {
        if !byte.is_ascii_alphabetic() {
            return true;
        }
        let hash_byte = hash[index / 2];
        let nibble = if index % 2 == 0 {
            hash_byte >> 4
        } else {
            hash_byte & 0x0f
        };
        byte.is_ascii_uppercase() == (nibble >= 8)
    })
}

#[cfg(test)]
mod tests {
    use eframe::egui;
    use sha2::{Digest as _, Sha256};

    use super::{QUIET_ZONE_MODULES, QrLayout, ReceiveQr, ReceiveQrError};

    const CHECKSUMMED_ADDRESS: &str = "0x52908400098527886E0F7030069857D2E4169EE7";
    const PAYMENT_URI: &str = "ethereum:0x52908400098527886E0F7030069857D2E4169EE7@11155111";

    fn matrix_digest(qr: &ReceiveQr) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(qr.code.size().to_be_bytes());
        for y in 0..qr.code.size() {
            for x in 0..qr.code.size() {
                digest.update([u8::from(qr.code.get_module(x, y))]);
            }
        }
        digest.finalize().into()
    }

    #[test]
    fn eip681_payload_and_checksum_validation_are_exact() -> Result<(), ReceiveQrError> {
        let qr = ReceiveQr::new(CHECKSUMMED_ADDRESS)?;
        assert_eq!(qr.payment_uri(), PAYMENT_URI);
        assert_eq!(qr.code.size(), 33);

        let payload_digest: [u8; 32] = Sha256::digest(qr.payment_uri().as_bytes()).into();
        assert_eq!(
            payload_digest,
            [
                192, 20, 240, 103, 212, 185, 204, 91, 142, 26, 31, 139, 187, 226, 61, 58, 102, 152,
                103, 118, 75, 236, 17, 20, 170, 173, 252, 153, 231, 106, 101, 42,
            ]
        );
        assert_eq!(
            matrix_digest(&qr),
            [
                131, 144, 58, 38, 34, 196, 128, 134, 250, 160, 95, 232, 117, 222, 8, 181, 233, 169,
                173, 246, 52, 218, 210, 55, 92, 71, 101, 33, 138, 202, 30, 161,
            ]
        );

        assert_eq!(
            ReceiveQr::new("0x52908400098527886e0f7030069857d2e4169ee7").err(),
            Some(ReceiveQrError::InvalidAddress)
        );
        assert_eq!(
            ReceiveQr::new("0x0000000000000000000000000000000000000000").err(),
            Some(ReceiveQrError::InvalidAddress)
        );
        Ok(())
    }

    #[test]
    fn native_eth_amount_is_canonical_integer_wei_and_uint256_bounded() {
        const MAXIMUM_WEI: &str =
            "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        const MAXIMUM_ETH: &str =
            "115792089237316195423570985008687907853269984665640564039457.584007913129639935";
        const OVERFLOW_ETH: &str =
            "115792089237316195423570985008687907853269984665640564039457.584007913129639936";

        for (amount_eth, expected_wei) in [
            ("0.000000000000000001", "1"),
            ("0.1", "100000000000000000"),
            ("1", "1000000000000000000"),
            ("1.2300", "1230000000000000000"),
            ("0001", "1000000000000000000"),
            (MAXIMUM_ETH, MAXIMUM_WEI),
        ] {
            let qr = ReceiveQr::new_with_native_eth_amount(CHECKSUMMED_ADDRESS, amount_eth)
                .expect("valid native ETH receive amount");
            assert_eq!(
                qr.payment_uri(),
                format!(
                    "ethereum:{CHECKSUMMED_ADDRESS}@{}?value={expected_wei}",
                    crate::rpc::SEPOLIA_CHAIN_ID
                )
            );
        }

        for invalid in [
            "",
            "0",
            "0.0",
            ".1",
            "1.",
            "+1",
            "-1",
            "1e2",
            "1E2",
            "1,2",
            " 1",
            "1 ",
            "1.0000000000000000001",
            "1.2.3",
            OVERFLOW_ETH,
        ] {
            assert_eq!(
                ReceiveQr::new_with_native_eth_amount(CHECKSUMMED_ADDRESS, invalid).err(),
                Some(ReceiveQrError::InvalidAmount)
            );
        }
        let overlong = "1".repeat(super::MAX_ETH_AMOUNT_INPUT_BYTES + 1);
        assert_eq!(
            ReceiveQr::new_with_native_eth_amount(CHECKSUMMED_ADDRESS, overlong.as_str()).err(),
            Some(ReceiveQrError::InvalidAmount)
        );
    }

    #[test]
    fn native_eth_amount_uri_and_matrix_are_one_exact_payload() -> Result<(), ReceiveQrError> {
        let qr = ReceiveQr::new_with_native_eth_amount(CHECKSUMMED_ADDRESS, "1.25")?;
        assert_eq!(
            qr.payment_uri(),
            format!(
                "ethereum:{CHECKSUMMED_ADDRESS}@{}?value=1250000000000000000",
                crate::rpc::SEPOLIA_CHAIN_ID
            )
        );
        assert_eq!(qr.code.size(), 41);

        let payload_digest: [u8; 32] = Sha256::digest(qr.payment_uri().as_bytes()).into();
        assert_eq!(
            payload_digest,
            [
                189, 39, 255, 98, 163, 97, 226, 214, 226, 229, 58, 23, 149, 57, 211, 218, 105, 218,
                200, 28, 198, 166, 119, 43, 108, 126, 115, 252, 107, 40, 213, 202,
            ]
        );
        assert_eq!(
            matrix_digest(&qr),
            [
                94, 55, 93, 190, 117, 50, 112, 133, 26, 214, 44, 165, 249, 37, 71, 21, 107, 173,
                161, 224, 238, 85, 24, 21, 151, 175, 14, 53, 181, 181, 108, 183,
            ]
        );
        Ok(())
    }

    #[test]
    fn layout_has_integer_physical_modules_and_exact_quiet_zone() -> Result<(), ReceiveQrError> {
        let layout = QrLayout::new(33, 1.25, 329.6)?;
        assert_eq!(layout.symbol_modules, 33);
        assert_eq!(layout.total_modules, 33 + QUIET_ZONE_MODULES * 2);
        assert_eq!(layout.module_pixels, 10);
        assert_eq!(layout.canvas_pixels(), 410);
        assert_eq!(layout.canvas_points(), 328.0);
        assert_eq!(layout.allocation_points(), 328.8);
        assert_eq!(layout.point_at_module(0.0, QUIET_ZONE_MODULES), 32.0);
        assert_eq!(
            layout.point_at_module(0.0, QUIET_ZONE_MODULES + layout.symbol_modules),
            296.0
        );
        assert_eq!(
            layout.canvas_points()
                - layout.point_at_module(0.0, QUIET_ZONE_MODULES + layout.symbol_modules),
            32.0
        );

        let exact_minimum = QrLayout::new(33, 1.0, 247.0)?;
        assert_eq!(exact_minimum.module_pixels, 6);
        assert_eq!(exact_minimum.canvas_pixels(), 246);
        assert_eq!(
            QrLayout::new(33, 1.0, 246.0).err(),
            Some(ReceiveQrError::InvalidLayout)
        );

        let high_dpi = QrLayout::new(33, 2.0, 200.0)?;
        assert_eq!(high_dpi.module_pixels, 9);
        assert!(high_dpi.allocation_points() <= 200.0);

        let twenty_percent_zoom = QrLayout::new(33, 0.2, 2_000.0)?;
        assert_eq!(twenty_percent_zoom.module_pixels, 6);
        assert!(twenty_percent_zoom.allocation_points() <= 2_000.0);
        let fifty_percent_zoom = QrLayout::new(33, 0.5, 1_000.0)?;
        assert_eq!(fifty_percent_zoom.module_pixels, 6);
        assert!(fifty_percent_zoom.allocation_points() <= 1_000.0);

        assert_eq!(
            QrLayout::new(20, 1.0, 500.0).err(),
            Some(ReceiveQrError::InvalidLayout)
        );
        assert_eq!(
            QrLayout::new(33, f32::NAN, 500.0).err(),
            Some(ReceiveQrError::InvalidLayout)
        );
        assert_eq!(
            QrLayout::new(33, 1.0, f32::NAN).err(),
            Some(ReceiveQrError::InvalidLayout)
        );
        Ok(())
    }

    #[test]
    fn egui_paint_emits_shapes_without_texture_allocation() -> Result<(), ReceiveQrError> {
        let qr = ReceiveQr::new(CHECKSUMMED_ADDRESS)?;
        let context = egui::Context::default();
        context.begin_pass(egui::RawInput::default());
        egui::CentralPanel::default().show(&context, |_ui| {});
        let _ = context.end_pass();
        context.begin_pass(egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::Vec2::splat(500.0),
            )),
            ..Default::default()
        });
        let metrics = egui::CentralPanel::default()
            .show(&context, |ui| qr.paint(ui))
            .inner?;
        let output = context.end_pass();

        assert_eq!(metrics.symbol_modules, 33);
        assert_eq!(metrics.total_modules, 41);
        assert_eq!(metrics.module_pixels, 8);
        assert!(metrics.dark_modules > 0);
        assert!(metrics.clip_rect.contains(metrics.canvas.min));
        assert!(metrics.clip_rect.contains(metrics.canvas.max));
        assert!(output.shapes.len() > metrics.dark_modules);
        let painted_rectangles = output
            .shapes
            .iter()
            .filter_map(|clipped| match &clipped.shape {
                egui::Shape::Rect(rectangle) => Some(rectangle),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            painted_rectangles
                .iter()
                .any(|rectangle| rectangle.fill == egui::Color32::WHITE)
        );
        let black_modules = painted_rectangles
            .iter()
            .filter(|rectangle| rectangle.fill == egui::Color32::BLACK)
            .collect::<Vec<_>>();
        assert_eq!(black_modules.len(), metrics.dark_modules);
        assert!(black_modules.iter().all(|rectangle| {
            (rectangle.rect.width() - metrics.module_pixels as f32).abs() < f32::EPSILON
                && (rectangle.rect.height() - metrics.module_pixels as f32).abs() < f32::EPSILON
        }));
        assert!(output.textures_delta.set.is_empty());

        let low_zoom_context = egui::Context::default();
        low_zoom_context.set_pixels_per_point(0.2);
        low_zoom_context.begin_pass(egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::Vec2::splat(2_000.0),
            )),
            ..Default::default()
        });
        egui::CentralPanel::default().show(&low_zoom_context, |_ui| {});
        let _ = low_zoom_context.end_pass();
        low_zoom_context.begin_pass(egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::Vec2::splat(2_000.0),
            )),
            ..Default::default()
        });
        let low_zoom_metrics = egui::CentralPanel::default()
            .show(&low_zoom_context, |ui| qr.paint(ui))
            .inner?;
        let low_zoom_output = low_zoom_context.end_pass();
        assert!((low_zoom_context.pixels_per_point() - 0.2).abs() < f32::EPSILON);
        assert_eq!(low_zoom_metrics.module_pixels, 6);
        assert!(low_zoom_metrics.dark_modules > 0);
        assert!(
            low_zoom_metrics
                .clip_rect
                .contains(low_zoom_metrics.canvas.min)
        );
        assert!(
            low_zoom_metrics
                .clip_rect
                .contains(low_zoom_metrics.canvas.max)
        );
        assert!(low_zoom_output.textures_delta.set.is_empty());

        let high_zoom_context = egui::Context::default();
        high_zoom_context.set_pixels_per_point(5.0);
        high_zoom_context.begin_pass(egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(160.0, 100.0),
            )),
            ..Default::default()
        });
        egui::CentralPanel::default().show(&high_zoom_context, |_ui| {});
        let _ = high_zoom_context.end_pass();
        high_zoom_context.begin_pass(egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(160.0, 100.0),
            )),
            ..Default::default()
        });
        let high_zoom_metrics = egui::CentralPanel::default()
            .show(&high_zoom_context, |ui| qr.paint(ui))
            .inner?;
        let high_zoom_output = high_zoom_context.end_pass();
        assert!((high_zoom_context.pixels_per_point() - 5.0).abs() < f32::EPSILON);
        assert!(high_zoom_metrics.module_pixels >= 6);
        assert!(high_zoom_metrics.module_pixels < 40);
        assert!(
            high_zoom_metrics
                .clip_rect
                .contains(high_zoom_metrics.canvas.min)
        );
        assert!(
            high_zoom_metrics
                .clip_rect
                .contains(high_zoom_metrics.canvas.max)
        );
        assert!(high_zoom_output.textures_delta.set.is_empty());

        let amount_qr = ReceiveQr::new_with_native_eth_amount(
            CHECKSUMMED_ADDRESS,
            "115792089237316195423570985008687907853269984665640564039457.584007913129639935",
        )?;
        let amount_context = egui::Context::default();
        amount_context.set_pixels_per_point(0.5);
        amount_context.begin_pass(egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::Vec2::splat(2_000.0),
            )),
            ..Default::default()
        });
        egui::CentralPanel::default().show(&amount_context, |_ui| {});
        let _ = amount_context.end_pass();
        amount_context.begin_pass(egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::Vec2::splat(2_000.0),
            )),
            ..Default::default()
        });
        let amount_metrics = egui::CentralPanel::default()
            .show(&amount_context, |ui| amount_qr.paint(ui))
            .inner?;
        let amount_output = amount_context.end_pass();
        assert!(amount_metrics.symbol_modules > 33);
        assert!(amount_metrics.total_modules > amount_metrics.symbol_modules);
        assert!(amount_metrics.module_pixels >= 6);
        assert!(amount_metrics.dark_modules > 0);
        assert!(amount_metrics.clip_rect.contains(amount_metrics.canvas.min));
        assert!(amount_metrics.clip_rect.contains(amount_metrics.canvas.max));
        assert!(amount_output.textures_delta.set.is_empty());
        Ok(())
    }
}
