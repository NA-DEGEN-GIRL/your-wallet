//! Round trips through the `WalletConnect` QR reader ([`super::qr_decode`]): codes made by the
//! wallet's encoder (`qrcodegen`), drawn like screenshots. 2026-11-17 S2: moved from
//! `walletconnect/tests.rs` to yw-app `ui/qr.rs`, so the decoder's tests did not need `qrcodegen`
//! (then a yw-app dependency). 2026-11-24 (spec/15 §11.4 S5-2): back next to the decoder,
//! unchanged, since `qrcodegen` is a yw-engine dependency with the screen model's QR
//! (`crate::screen::qr`).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap
)]

use qrcodegen::{QrCode, QrCodeEcc};

use super::qr_decode::{Gray, decode, decode_bgra_text};

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
