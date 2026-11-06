//! A QR Code decoder for screenshots (spec/13 §6, ISO/IEC 18004): grayscale → binarisation
//! (global Otsu, then a local-block threshold, each also inverted) → finder-pattern detection
//! (1:1:3:1:1 runs on rows, confirmed on the column and re-centred on the row) → the best
//! right-angle triple → version estimate → perspective transform (affine from the three finder
//! centres, then a homography with the bottom-right alignment pattern) → module sampling →
//! format information (BCH, nearest of the 32 codes) → version information (v7+) → unmasking →
//! codeword zig-zag → de-interleaving → Reed–Solomon correction over GF(256) (0x11D, roots
//! α^0…α^(n−1), Berlekamp–Massey, Chien, Forney) → numeric, alphanumeric and byte segments
//! (ECI headers skipped). Kanji and structured append are not supported (a `wc:` URI is byte
//! mode).
//!
//! The module layout (function patterns, zig-zag order, masks, block tables) is the mirror of
//! `qrcodegen` 1.8.0 (`draw_function_patterns`, `draw_codewords`, `apply_mask`,
//! `add_ecc_and_interleave`, `ECC_CODEWORDS_PER_BLOCK`, `NUM_ERROR_CORRECTION_BLOCKS`), which the
//! tests use as the encoder.
#![deny(clippy::indexing_slicing)]

/// Largest image the decoder looks at (pixels).
pub const MAX_PIXELS: usize = 64 * 1_024 * 1_024;

/// A grayscale image (0 = black, 255 = white).
#[derive(Clone, PartialEq, Eq)]
pub struct Gray {
    width: usize,
    height: usize,
    data: Vec<u8>,
}

impl core::fmt::Debug for Gray {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "Gray({}x{})", self.width, self.height)
    }
}

impl Gray {
    /// From luminance bytes (`width × height`).
    #[must_use]
    pub fn new(width: usize, height: usize, data: Vec<u8>) -> Option<Self> {
        (width > 0
            && height > 0
            && width.checked_mul(height)? == data.len()
            && data.len() <= MAX_PIXELS)
            .then_some(Self {
                width,
                height,
                data,
            })
    }

    /// From BGRA pixels (top row first); transparent pixels count as white.
    #[must_use]
    pub fn from_bgra(width: usize, height: usize, pixels: &[u8]) -> Option<Self> {
        if width.checked_mul(height)?.checked_mul(4)? != pixels.len() {
            return None;
        }
        let data = pixels
            .chunks_exact(4)
            .map(|pixel| {
                let [b, g, r, a] =
                    [0, 1, 2, 3].map(|i| u32::from(pixel.get(i).copied().unwrap_or(0)));
                let luma = (r * 299 + g * 587 + b * 114) / 1_000;
                // Composite over white.
                let value = (luma * a + 255 * (255 - a)) / 255;
                u8::try_from(value.min(255)).unwrap_or(255)
            })
            .collect();
        Self::new(width, height, data)
    }

    fn at(&self, x: usize, y: usize) -> u8 {
        self.data.get(y * self.width + x).copied().unwrap_or(255)
    }
}

/// Parses `CF_DIB` clipboard bytes (`BITMAPINFOHEADER`/V4/V5 + optional masks/palette + pixels;
/// 8-bit palettised, 24-bit and 32-bit, bottom-up or top-down) into BGRA pixels.
#[must_use]
pub fn dib_to_bgra(bytes: &[u8]) -> Option<(usize, usize, Vec<u8>)> {
    let u32_at = |offset: usize| -> Option<u32> {
        Some(u32::from_le_bytes(
            bytes.get(offset..offset + 4)?.try_into().ok()?,
        ))
    };
    let u16_at = |offset: usize| -> Option<u16> {
        Some(u16::from_le_bytes(
            bytes.get(offset..offset + 2)?.try_into().ok()?,
        ))
    };
    let header = usize::try_from(u32_at(0)?).ok()?;
    if !(40..=124).contains(&header) {
        return None;
    }
    let width = i32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?);
    let height = i32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?);
    let bits = u16_at(14)?;
    let compression = u32_at(16)?;
    let used = usize::try_from(u32_at(32)?).ok()?;
    let top_down = height < 0;
    let width = usize::try_from(width).ok().filter(|w| *w > 0)?;
    let height = usize::try_from(height.unsigned_abs())
        .ok()
        .filter(|h| *h > 0)?;
    if width.checked_mul(height)? > MAX_PIXELS {
        return None;
    }
    // BI_RGB = 0, BI_BITFIELDS = 3 (32-bit with the standard masks in practice).
    if compression != 0 && compression != 3 {
        return None;
    }
    let masks = if compression == 3 && header == 40 {
        12
    } else {
        0
    };
    let palette_len = if bits <= 8 {
        if used == 0 { 1_usize << bits } else { used }
    } else {
        0
    };
    let palette_start = header + masks;
    let pixels_start = palette_start + palette_len * 4;
    let row_bytes = (width * usize::from(bits)).div_ceil(32) * 4;
    let mut out = Vec::with_capacity(width * height * 4);
    for row in 0..height {
        let source_row = if top_down { row } else { height - 1 - row };
        let start = pixels_start + source_row * row_bytes;
        let line = bytes.get(start..start + row_bytes)?;
        for x in 0..width {
            let pixel: [u8; 4] = match bits {
                32 => {
                    let p = line.get(x * 4..x * 4 + 4)?;
                    // CF_DIB alpha is often 0 for opaque screenshots: treat as opaque.
                    [*p.first()?, *p.get(1)?, *p.get(2)?, 255]
                }
                24 => {
                    let p = line.get(x * 3..x * 3 + 3)?;
                    [*p.first()?, *p.get(1)?, *p.get(2)?, 255]
                }
                8 => {
                    let index = usize::from(*line.get(x)?);
                    let entry =
                        bytes.get(palette_start + index * 4..palette_start + index * 4 + 3)?;
                    [*entry.first()?, *entry.get(1)?, *entry.get(2)?, 255]
                }
                _ => return None,
            };
            out.extend_from_slice(&pixel);
        }
    }
    Some((width, height, out))
}

// ----- numeric helpers ---------------------------------------------------------------------

fn fl(value: usize) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}

/// `floor(value)` as an index below `limit`.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is checked to lie in 0..limit (≤ 2^26) before the cast"
)]
fn index_of(value: f64, limit: usize) -> Option<usize> {
    if value.is_nan() || value < 0.0 || value >= fl(limit) {
        return None;
    }
    Some(value.floor() as usize)
}

/// `round(value)` as a small non-negative integer.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is checked to lie in 0..=1e6 before the cast"
)]
fn round_small(value: f64) -> Option<usize> {
    if value.is_nan() || !(0.0..=1e6).contains(&value) {
        return None;
    }
    Some(value.round() as usize)
}

// ----- binarisation ------------------------------------------------------------------------

/// A black/white image (`true` = dark).
struct Bits {
    width: usize,
    height: usize,
    dark: Vec<bool>,
}

impl Bits {
    fn get(&self, x: usize, y: usize) -> bool {
        x < self.width
            && y < self.height
            && self.dark.get(y * self.width + x).copied().unwrap_or(false)
    }

    fn at(&self, x: f64, y: f64) -> Option<bool> {
        Some(self.get(index_of(x, self.width)?, index_of(y, self.height)?))
    }

    fn inverted(&self) -> Self {
        Self {
            width: self.width,
            height: self.height,
            dark: self.dark.iter().map(|dark| !dark).collect(),
        }
    }
}

fn otsu(gray: &Gray) -> u8 {
    let mut histogram = [0_u64; 256];
    for value in &gray.data {
        if let Some(slot) = histogram.get_mut(usize::from(*value)) {
            *slot += 1;
        }
    }
    let total: u64 = histogram.iter().sum();
    let sum_all: u64 = histogram
        .iter()
        .enumerate()
        .map(|(value, count)| u64::try_from(value).unwrap_or(0) * count)
        .sum();
    let (mut weight_b, mut sum_b) = (0_u64, 0_u64);
    let (mut best, mut best_between) = (128_u8, 0.0_f64);
    for (value, count) in histogram.iter().enumerate() {
        weight_b += count;
        if weight_b == 0 {
            continue;
        }
        let weight_f = total - weight_b;
        if weight_f == 0 {
            break;
        }
        sum_b += u64::try_from(value).unwrap_or(0) * count;
        let to_f =
            |n: u64| f64::from(u32::try_from(n.min(u64::from(u32::MAX))).unwrap_or(u32::MAX));
        let mean_b = to_f(sum_b) / to_f(weight_b);
        let mean_f = to_f(sum_all - sum_b) / to_f(weight_f);
        let between = to_f(weight_b) * to_f(weight_f) * (mean_b - mean_f).powi(2);
        if between > best_between {
            best_between = between;
            best = u8::try_from(value).unwrap_or(128);
        }
    }
    best
}

fn binarize_global(gray: &Gray) -> Bits {
    let threshold = otsu(gray);
    Bits {
        width: gray.width,
        height: gray.height,
        dark: gray.data.iter().map(|value| *value <= threshold).collect(),
    }
}

/// Local threshold: the mean of the 5×5 neighbourhood of 8×8 blocks; flat neighbourhoods
/// (range < 24) fall back to the global threshold.
fn binarize_local(gray: &Gray) -> Bits {
    const BLOCK: usize = 8;
    let global = otsu(gray);
    let blocks_x = gray.width.div_ceil(BLOCK);
    let blocks_y = gray.height.div_ceil(BLOCK);
    let mut means = vec![0_u32; blocks_x * blocks_y];
    let mut mins = vec![255_u8; blocks_x * blocks_y];
    let mut maxs = vec![0_u8; blocks_x * blocks_y];
    for by in 0..blocks_y {
        for bx in 0..blocks_x {
            let (mut sum, mut count, mut low, mut high) = (0_u32, 0_u32, 255_u8, 0_u8);
            for y in by * BLOCK..((by + 1) * BLOCK).min(gray.height) {
                for x in bx * BLOCK..((bx + 1) * BLOCK).min(gray.width) {
                    let value = gray.at(x, y);
                    sum += u32::from(value);
                    count += 1;
                    low = low.min(value);
                    high = high.max(value);
                }
            }
            let index = by * blocks_x + bx;
            if let (Some(mean), Some(min), Some(max)) = (
                means.get_mut(index),
                mins.get_mut(index),
                maxs.get_mut(index),
            ) {
                *mean = sum / count.max(1);
                *min = low;
                *max = high;
            }
        }
    }
    let mut thresholds = vec![global; blocks_x * blocks_y];
    for by in 0..blocks_y {
        for bx in 0..blocks_x {
            let (mut sum, mut count, mut low, mut high) = (0_u32, 0_u32, 255_u8, 0_u8);
            for ny in by.saturating_sub(2)..(by + 3).min(blocks_y) {
                for nx in bx.saturating_sub(2)..(bx + 3).min(blocks_x) {
                    let index = ny * blocks_x + nx;
                    sum += means.get(index).copied().unwrap_or(0);
                    count += 1;
                    low = low.min(mins.get(index).copied().unwrap_or(255));
                    high = high.max(maxs.get(index).copied().unwrap_or(0));
                }
            }
            if high.saturating_sub(low) >= 24
                && let Some(slot) = thresholds.get_mut(by * blocks_x + bx)
            {
                *slot = u8::try_from(sum / count.max(1)).unwrap_or(global);
            }
        }
    }
    let mut dark = Vec::with_capacity(gray.data.len());
    for y in 0..gray.height {
        for x in 0..gray.width {
            let threshold = thresholds
                .get((y / BLOCK) * blocks_x + x / BLOCK)
                .copied()
                .unwrap_or(global);
            dark.push(gray.at(x, y) < threshold);
        }
    }
    Bits {
        width: gray.width,
        height: gray.height,
        dark,
    }
}

// ----- finder patterns ---------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct Point {
    x: f64,
    y: f64,
}

impl Point {
    fn distance(self, other: Self) -> f64 {
        ((self.x - other.x).powi(2) + (self.y - other.y).powi(2)).sqrt()
    }
}

#[derive(Clone, Copy, Debug)]
struct Candidate {
    center: Point,
    module: f64,
    count: u32,
}

/// Whether five run lengths look like 1:1:3:1:1.
fn ratio_ok(runs: &[usize; 5]) -> Option<f64> {
    let total: usize = runs.iter().sum();
    if total < 7 || runs.contains(&0) {
        return None;
    }
    let module = fl(total) / 7.0;
    let tolerance = module * 0.7;
    let [outer_left, inner_left, center, inner_right, outer_right] = runs.map(fl);
    ((outer_left - module).abs() < tolerance
        && (inner_left - module).abs() < tolerance
        && (center - 3.0 * module).abs() < 3.0 * tolerance
        && (inner_right - module).abs() < tolerance
        && (outer_right - module).abs() < tolerance)
        .then_some(module)
}

/// Runs through `(x, y)` along `(dx, dy)` (−1/0/1 steps): the centre dark run and the four runs
/// around it, `None` when the pattern is not there. Returns the runs and the centre offset.
fn cross_runs(
    bits: &Bits,
    x: usize,
    y: usize,
    dx: isize,
    dy: isize,
    max_run: usize,
) -> Option<([usize; 5], f64)> {
    if !bits.get(x, y) {
        return None;
    }
    let step = |x: usize, y: usize, sign: isize| -> Option<(usize, usize)> {
        let nx = x.checked_add_signed(dx * sign)?;
        let ny = y.checked_add_signed(dy * sign)?;
        (nx < bits.width && ny < bits.height).then_some((nx, ny))
    };
    // Walk one way: [centre part, white, black] lengths.
    let walk = |sign: isize| -> Option<[usize; 3]> {
        let mut counts = [0_usize; 3];
        let (mut cx, mut cy) = (x, y);
        let mut state = 0_usize;
        let mut expected_dark = true;
        loop {
            let Some((nx, ny)) = step(cx, cy, sign) else {
                // Edge: the outer run may end at the image border.
                return (state == 2 && counts[2] > 0).then_some(counts);
            };
            let dark = bits.get(nx, ny);
            if dark != expected_dark {
                state += 1;
                if state == 3 {
                    return Some(counts);
                }
                expected_dark = !expected_dark;
            }
            let slot = counts.get_mut(state)?;
            *slot += 1;
            if *slot > max_run {
                return None;
            }
            cx = nx;
            cy = ny;
        }
    };
    let back = walk(-1)?;
    let forward = walk(1)?;
    let runs = [
        back[2],
        back[1],
        back[0] + forward[0] + 1,
        forward[1],
        forward[2],
    ];
    ratio_ok(&runs)?;
    // Centre offset from (x, y) along the direction.
    let offset = (fl(forward[0]) - fl(back[0])) / 2.0;
    Some((runs, offset))
}

fn find_candidates(bits: &Bits) -> Vec<Candidate> {
    let mut candidates: Vec<Candidate> = Vec::new();
    let row_step = if bits.height > 1_500 { 2 } else { 1 };
    let mut runs: Vec<(bool, usize, usize)> = Vec::new(); // (dark, start, length)
    for y in (0..bits.height).step_by(row_step) {
        runs.clear();
        let mut start = 0;
        for x in 1..=bits.width {
            if x == bits.width || bits.get(x, y) != bits.get(start, y) {
                runs.push((bits.get(start, y), start, x - start));
                start = x;
            }
        }
        for index in 4..runs.len() {
            let window = runs.get(index - 4..=index).unwrap_or(&[]);
            let &[r0, r1, r2, r3, r4] = window else {
                continue;
            };
            if !r0.0 {
                continue;
            }
            let lengths = [r0.2, r1.2, r2.2, r3.2, r4.2];
            let Some(module) = ratio_ok(&lengths) else {
                continue;
            };
            let total: usize = lengths.iter().sum();
            let max_run = total * 2;
            let cx = r2.1 + r2.2 / 2;
            // Vertical cross-check, then the horizontal one through the refined centre.
            let Some((vertical, dy)) = cross_runs(bits, cx, y, 0, 1, max_run) else {
                continue;
            };
            let vertical_total: usize = vertical.iter().sum();
            if fl(vertical_total.abs_diff(total)) > 0.5 * fl(total) {
                continue;
            }
            let Some(cy) = index_of(fl(y) + dy + 0.5, bits.height) else {
                continue;
            };
            let Some((horizontal, dx)) = cross_runs(bits, cx, cy, 1, 0, max_run) else {
                continue;
            };
            let horizontal_total: usize = horizontal.iter().sum();
            let module = (fl(horizontal_total) + fl(vertical_total)) / 14.0 * 0.5 + module * 0.5;
            let center = Point {
                x: fl(cx) + dx + 0.5,
                y: fl(cy) + 0.5,
            };
            if let Some(known) = candidates.iter_mut().find(|known| {
                (known.center.x - center.x).abs() <= known.module.max(module) * 1.5
                    && (known.center.y - center.y).abs() <= known.module.max(module) * 1.5
                    && (known.module - module).abs() <= known.module.max(module) * 0.5
            }) {
                let weight = f64::from(known.count);
                known.center.x = (known.center.x * weight + center.x) / (weight + 1.0);
                known.center.y = (known.center.y * weight + center.y) / (weight + 1.0);
                known.module = (known.module * weight + module) / (weight + 1.0);
                known.count += 1;
            } else if candidates.len() < 256 {
                candidates.push(Candidate {
                    center,
                    module,
                    count: 1,
                });
            }
        }
    }
    candidates.sort_by_key(|candidate| core::cmp::Reverse(candidate.count));
    candidates.truncate(12);
    candidates
}

/// Right-angle triples ordered `(top-left, top-right, bottom-left)`, best first.
fn triples(candidates: &[Candidate]) -> Vec<([Point; 3], f64)> {
    let mut out = Vec::new();
    for i in 0..candidates.len() {
        for j in i + 1..candidates.len() {
            for k in j + 1..candidates.len() {
                let (Some(first), Some(second), Some(third)) =
                    (candidates.get(i), candidates.get(j), candidates.get(k))
                else {
                    continue;
                };
                let modules = [first.module, second.module, third.module];
                let low = modules.iter().copied().fold(f64::MAX, f64::min);
                let high = modules.iter().copied().fold(0.0, f64::max);
                if high / low > 1.5 {
                    continue;
                }
                let module = (first.module + second.module + third.module) / 3.0;
                // The corner opposite the longest side is the top-left finder.
                let d12 = first.center.distance(second.center);
                let d13 = first.center.distance(third.center);
                let d23 = second.center.distance(third.center);
                let (top_left, corner_one, corner_two, long, s1, s2) = if d23 >= d12 && d23 >= d13 {
                    (first, second, third, d23, d12, d13)
                } else if d13 >= d12 {
                    (second, first, third, d13, d12, d23)
                } else {
                    (third, first, second, d12, d13, d23)
                };
                let (p, q) = (corner_one, corner_two);
                if s1 < 10.0 * module || s2 < 10.0 * module {
                    continue;
                }
                let squareness = (s1 - s2).abs() / s1.max(s2);
                let right = (long * long - s1 * s1 - s2 * s2).abs() / (long * long);
                if squareness > 0.25 || right > 0.25 {
                    continue;
                }
                // y grows downwards: (TR − TL) × (BL − TL) > 0 for the reading orientation.
                let cross = (p.center.x - top_left.center.x) * (q.center.y - top_left.center.y)
                    - (p.center.y - top_left.center.y) * (q.center.x - top_left.center.x);
                let (top_right, bottom_left) = if cross > 0.0 { (p, q) } else { (q, p) };
                out.push((
                    [top_left.center, top_right.center, bottom_left.center],
                    squareness + right,
                ));
            }
        }
    }
    out.sort_by(|a, b| a.1.total_cmp(&b.1));
    out.truncate(6);
    out
}

// ----- geometry ----------------------------------------------------------------------------

/// A 3×3 projective transform (the row-vector convention of the `ZXing` `PerspectiveTransform`).
#[derive(Clone, Copy, Debug)]
struct Transform([f64; 9]);

impl Transform {
    /// Unit square (0,0),(1,0),(1,1),(0,1) → the quadrilateral.
    fn square_to_quad(q: [Point; 4]) -> Self {
        let [p0, p1, p2, p3] = q;
        let dx3 = p0.x - p1.x + p2.x - p3.x;
        let dy3 = p0.y - p1.y + p2.y - p3.y;
        if dx3.abs() < 1e-9 && dy3.abs() < 1e-9 {
            Self([
                p1.x - p0.x,
                p1.y - p0.y,
                0.0,
                p2.x - p1.x,
                p2.y - p1.y,
                0.0,
                p0.x,
                p0.y,
                1.0,
            ])
        } else {
            let dx1 = p1.x - p2.x;
            let dx2 = p3.x - p2.x;
            let dy1 = p1.y - p2.y;
            let dy2 = p3.y - p2.y;
            let denominator = dx1 * dy2 - dx2 * dy1;
            let a13 = (dx3 * dy2 - dx2 * dy3) / denominator;
            let a23 = (dx1 * dy3 - dx3 * dy1) / denominator;
            Self([
                p1.x - p0.x + a13 * p1.x,
                p1.y - p0.y + a13 * p1.y,
                a13,
                p3.x - p0.x + a23 * p3.x,
                p3.y - p0.y + a23 * p3.y,
                a23,
                p0.x,
                p0.y,
                1.0,
            ])
        }
    }

    /// The adjugate (inverse up to scale, which a projective transform ignores).
    fn adjoint(&self) -> Self {
        let [a11, a12, a13, a21, a22, a23, a31, a32, a33] = self.0;
        Self([
            a22 * a33 - a23 * a32,
            a13 * a32 - a12 * a33,
            a12 * a23 - a13 * a22,
            a23 * a31 - a21 * a33,
            a11 * a33 - a13 * a31,
            a13 * a21 - a11 * a23,
            a21 * a32 - a22 * a31,
            a12 * a31 - a11 * a32,
            a11 * a22 - a12 * a21,
        ])
    }

    fn times(&self, other: &Self) -> Self {
        let a = &self.0;
        let b = &other.0;
        let at = |m: &[f64; 9], r: usize, c: usize| m.get(r * 3 + c).copied().unwrap_or(0.0);
        let mut out = [0.0; 9];
        for (index, slot) in out.iter_mut().enumerate() {
            let (r, c) = (index / 3, index % 3);
            *slot = (0..3).map(|k| at(a, r, k) * at(b, k, c)).sum();
        }
        Self(out)
    }

    /// `from` quadrilateral → `to` quadrilateral (corners in the same order).
    fn quad_to_quad(from: [Point; 4], to: [Point; 4]) -> Self {
        let to_square = Self::square_to_quad(from).adjoint();
        to_square.times(&Self::square_to_quad(to))
    }

    fn apply(&self, x: f64, y: f64) -> Point {
        let [a11, a12, a13, a21, a22, a23, a31, a32, a33] = self.0;
        let denominator = a13 * x + a23 * y + a33;
        Point {
            x: (a11 * x + a21 * y + a31) / denominator,
            y: (a12 * x + a22 * y + a32) / denominator,
        }
    }
}

/// Samples a `size × size` module grid through `transform` (module coordinates → image).
fn sample(bits: &Bits, transform: &Transform, size: usize) -> Option<Vec<bool>> {
    let mut grid = Vec::with_capacity(size * size);
    for y in 0..size {
        for x in 0..size {
            let point = transform.apply(fl(x) + 0.5, fl(y) + 0.5);
            grid.push(bits.at(point.x, point.y)?);
        }
    }
    Some(grid)
}

/// Searches the bottom-right alignment pattern (dark centre, light ring, dark ring) around its
/// position predicted by `affine`; returns its image centre.
fn find_alignment(bits: &Bits, affine: &Transform, size: usize) -> Option<Point> {
    let center = fl(size) - 6.5;
    let expected = affine.apply(center, center);
    let origin = affine.apply(center - 1.0, center);
    let module = expected.distance(origin).max(1.0);
    let unit_x = affine.apply(center + 1.0, center);
    let unit_y = affine.apply(center, center + 1.0);
    let (ux, uy) = (unit_x.x - expected.x, unit_x.y - expected.y);
    let (vx, vy) = (unit_y.x - expected.x, unit_y.y - expected.y);
    let radius = (module * 5.0).max(4.0);
    let step = (module / 3.0).max(0.5);
    let mut best: Option<(u32, f64, Point)> = None;
    let mut oy = -radius;
    while oy <= radius {
        let mut ox = -radius;
        while ox <= radius {
            let p = Point {
                x: expected.x + ox,
                y: expected.y + oy,
            };
            let mut score = 0_u32;
            for j in -2_i32..=2 {
                for i in -2_i32..=2 {
                    let (fi, fj) = (f64::from(i), f64::from(j));
                    let want_dark = i.abs().max(j.abs()) != 1;
                    if bits.at(p.x + fi * ux + fj * vx, p.y + fi * uy + fj * vy) == Some(want_dark)
                    {
                        score += 1;
                    }
                }
            }
            let distance = ox.hypot(oy);
            let better = match best {
                None => true,
                Some((known, known_distance, _)) => {
                    score > known || (score == known && distance < known_distance)
                }
            };
            if better {
                best = Some((score, distance, p));
            }
            ox += step;
        }
        oy += step;
    }
    best.filter(|(score, _, _)| *score >= 23).map(|(_, _, p)| p)
}

// ----- QR structure ------------------------------------------------------------------------

const ECC_CODEWORDS_PER_BLOCK: [[u8; 41]; 4] = [
    [
        0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28,
        30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    ],
    [
        0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28,
        28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    ],
    [
        0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30,
        30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    ],
    [
        0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24,
        30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    ],
];

const NUM_ERROR_CORRECTION_BLOCKS: [[u8; 41]; 4] = [
    [
        0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13,
        14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25,
    ],
    [
        0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21,
        23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49,
    ],
    [
        0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29,
        34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68,
    ],
    [
        0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32,
        35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81,
    ],
];

/// Error-correction level as the table row (Low, Medium, Quartile, High).
fn ecl_row(format_bits: u32) -> usize {
    match format_bits {
        1 => 0,
        0 => 1,
        3 => 2,
        _ => 3,
    }
}

fn raw_data_modules(version: usize) -> usize {
    let mut result = (16 * version + 128) * version + 64;
    if version >= 2 {
        let numalign = version / 7 + 2;
        result -= (25 * numalign - 10) * numalign - 55;
        if version >= 7 {
            result -= 36;
        }
    }
    result
}

fn alignment_positions(version: usize) -> Vec<usize> {
    if version == 1 {
        return Vec::new();
    }
    let size = version * 4 + 17;
    let numalign = version / 7 + 2;
    let step = if version == 32 {
        26
    } else {
        (version * 4 + numalign * 2 + 1) / (numalign * 2 - 2) * 2
    };
    let mut result: Vec<usize> = (0..numalign - 1).map(|i| size - 7 - i * step).collect();
    result.push(6);
    result.reverse();
    result
}

fn format_code(data: u32) -> u32 {
    let mut rem = data;
    for _ in 0..10 {
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    }
    ((data << 10) | rem) ^ 0x5412
}

fn version_code(version: u32) -> u32 {
    let mut rem = version;
    for _ in 0..12 {
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
    }
    (version << 12) | rem
}

/// The module grid of one QR candidate.
struct Grid {
    size: usize,
    dark: Vec<bool>,
}

impl Grid {
    fn get(&self, x: usize, y: usize) -> bool {
        self.dark.get(y * self.size + x).copied().unwrap_or(false)
    }

    /// `(ecl format bits, mask)` from the nearest valid format code (≤ 3 bit errors).
    fn format(&self) -> Option<(u32, u32)> {
        let size = self.size;
        let bit = |x: usize, y: usize| u32::from(self.get(x, y));
        let mut first = 0_u32;
        for i in 0..6 {
            first |= bit(8, i) << i;
        }
        first |= bit(8, 7) << 6;
        first |= bit(8, 8) << 7;
        first |= bit(7, 8) << 8;
        for i in 9..15 {
            first |= bit(14 - i, 8) << i;
        }
        let mut second = 0_u32;
        for i in 0..8 {
            second |= bit(size - 1 - i, 8) << i;
        }
        for i in 8..15 {
            second |= bit(8, size - 15 + i) << i;
        }
        let mut best: Option<(u32, u32)> = None;
        for data in 0..32_u32 {
            let code = format_code(data);
            let distance = (code ^ first)
                .count_ones()
                .min((code ^ second).count_ones());
            if best.is_none_or(|(_, known)| distance < known) {
                best = Some((data, distance));
            }
        }
        let (data, distance) = best?;
        (distance <= 3).then_some((data >> 3, data & 7))
    }

    /// The version: from the size (v1–6) or the version blocks (v7+, ≤ 3 bit errors).
    fn version(&self) -> Option<usize> {
        let from_size = (self.size.checked_sub(17)?) / 4;
        if !(1..=40).contains(&from_size) || from_size * 4 + 17 != self.size {
            return None;
        }
        if from_size < 7 {
            return Some(from_size);
        }
        let size = self.size;
        let (mut first, mut second) = (0_u32, 0_u32);
        for i in 0..18 {
            let a = size - 11 + i % 3;
            let b = i / 3;
            first |= u32::from(self.get(a, b)) << i;
            second |= u32::from(self.get(b, a)) << i;
        }
        let mut best: Option<(u32, u32)> = None;
        for version in 7..=40_u32 {
            let code = version_code(version);
            let distance = (code ^ first)
                .count_ones()
                .min((code ^ second).count_ones());
            if best.is_none_or(|(_, known)| distance < known) {
                best = Some((version, distance));
            }
        }
        let (version, distance) = best?;
        let version = usize::try_from(version).ok()?;
        (distance <= 3 && version == from_size).then_some(version)
    }
}

fn function_modules(version: usize) -> Vec<bool> {
    let size = version * 4 + 17;
    let mut function = vec![false; size * size];
    let mut mark = |x: usize, y: usize| {
        if x < size
            && y < size
            && let Some(slot) = function.get_mut(y * size + x)
        {
            *slot = true;
        }
    };
    for i in 0..size {
        mark(6, i);
        mark(i, 6);
    }
    for (cx, cy) in [(3, 3), (size - 4, 3), (3, size - 4)] {
        for dy in 0..9 {
            for dx in 0..9 {
                if let (Some(x), Some(y)) = ((cx + dx).checked_sub(4), (cy + dy).checked_sub(4)) {
                    mark(x, y);
                }
            }
        }
    }
    let positions = alignment_positions(version);
    let count = positions.len();
    for (i, &ax) in positions.iter().enumerate() {
        for (j, &ay) in positions.iter().enumerate() {
            let corner = (i == 0 && (j == 0 || j == count - 1)) || (i == count - 1 && j == 0);
            if corner {
                continue;
            }
            for dy in 0..5 {
                for dx in 0..5 {
                    mark(ax + dx - 2, ay + dy - 2);
                }
            }
        }
    }
    // Format areas (both copies) and the dark module.
    for i in 0..9 {
        mark(8, i);
        mark(i, 8);
    }
    for i in 0..8 {
        mark(size - 1 - i, 8);
        mark(8, size - 1 - i);
    }
    if version >= 7 {
        for i in 0..18 {
            let a = size - 11 + i % 3;
            let b = i / 3;
            mark(a, b);
            mark(b, a);
        }
    }
    function
}

fn mask_bit(mask: u32, x: usize, y: usize) -> bool {
    match mask {
        0 => (x + y).is_multiple_of(2),
        1 => y.is_multiple_of(2),
        2 => x.is_multiple_of(3),
        3 => (x + y).is_multiple_of(3),
        4 => (x / 3 + y / 2).is_multiple_of(2),
        5 => x * y % 2 + x * y % 3 == 0,
        6 => (x * y % 2 + x * y % 3).is_multiple_of(2),
        _ => ((x + y) % 2 + x * y % 3).is_multiple_of(2),
    }
}

fn read_codewords(grid: &Grid, version: usize, mask: u32) -> Vec<u8> {
    let size = grid.size;
    let function = function_modules(version);
    let total = raw_data_modules(version) / 8;
    let mut out = vec![0_u8; total];
    let mut bit = 0_usize;
    let mut right = size - 1;
    loop {
        if right == 6 {
            right = 5;
        }
        for vert in 0..size {
            for j in 0..2 {
                let x = right - j;
                let upward = (right + 1) & 2 == 0;
                let y = if upward { size - 1 - vert } else { vert };
                if !function.get(y * size + x).copied().unwrap_or(true) && bit < total * 8 {
                    let dark = grid.get(x, y) ^ mask_bit(mask, x, y);
                    if dark && let Some(byte) = out.get_mut(bit >> 3) {
                        *byte |= 0x80 >> (bit & 7);
                    }
                    bit += 1;
                }
            }
        }
        if right < 3 {
            break;
        }
        right -= 2;
    }
    out
}

// ----- Reed–Solomon over GF(256) -----------------------------------------------------------

struct Field {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Field {
    fn new() -> Self {
        let mut exp = [0_u8; 512];
        let mut log = [0_u8; 256];
        let mut value = 1_u16;
        for i in 0..255_usize {
            let byte = u8::try_from(value).unwrap_or(0);
            if let Some(slot) = exp.get_mut(i) {
                *slot = byte;
            }
            if let Some(slot) = log.get_mut(usize::from(byte)) {
                *slot = u8::try_from(i).unwrap_or(0);
            }
            value <<= 1;
            if value & 0x100 != 0 {
                value ^= 0x11D;
            }
        }
        for i in 255..512 {
            let early = exp.get(i - 255).copied().unwrap_or(0);
            if let Some(slot) = exp.get_mut(i) {
                *slot = early;
            }
        }
        Self { exp, log }
    }

    fn exp(&self, power: usize) -> u8 {
        self.exp.get(power % 255).copied().unwrap_or(0)
    }

    fn log(&self, value: u8) -> usize {
        usize::from(self.log.get(usize::from(value)).copied().unwrap_or(0))
    }

    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp(self.log(a) + self.log(b))
        }
    }

    fn div(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp(self.log(a) + 255 - self.log(b))
        }
    }

    fn inverse(&self, a: u8) -> u8 {
        self.div(1, a)
    }

    /// Evaluates a polynomial stored lowest degree first.
    fn eval_low(&self, poly: &[u8], x: u8) -> u8 {
        poly.iter()
            .rev()
            .fold(0, |acc, coefficient| self.mul(acc, x) ^ coefficient)
    }
}

/// Corrects `block` (data ‖ ecc, highest degree first) in place; `false` when uncorrectable.
fn rs_correct(field: &Field, block: &mut [u8], ecc_len: usize) -> bool {
    let n = block.len();
    let syndromes: Vec<u8> = (0..ecc_len)
        .map(|j| {
            let x = field.exp(j);
            block.iter().fold(0, |acc, byte| field.mul(acc, x) ^ byte)
        })
        .collect();
    if syndromes.iter().all(|s| *s == 0) {
        return true;
    }
    // Berlekamp–Massey (polynomials lowest degree first).
    let mut locator = vec![1_u8];
    let mut previous = vec![1_u8];
    let mut length = 0_usize;
    let mut shift = 1_usize;
    let mut last_discrepancy = 1_u8;
    for step in 0..ecc_len {
        let mut discrepancy = syndromes.get(step).copied().unwrap_or(0);
        for i in 1..=length {
            discrepancy ^= field.mul(
                locator.get(i).copied().unwrap_or(0),
                syndromes.get(step - i).copied().unwrap_or(0),
            );
        }
        if discrepancy == 0 {
            shift += 1;
            continue;
        }
        let factor = field.div(discrepancy, last_discrepancy);
        let mut next = locator.clone();
        if next.len() < previous.len() + shift {
            next.resize(previous.len() + shift, 0);
        }
        for (i, coefficient) in previous.iter().enumerate() {
            if let Some(slot) = next.get_mut(i + shift) {
                *slot ^= field.mul(factor, *coefficient);
            }
        }
        if 2 * length <= step {
            previous = core::mem::replace(&mut locator, next);
            length = step + 1 - length;
            last_discrepancy = discrepancy;
            shift = 1;
        } else {
            locator = next;
            shift += 1;
        }
    }
    if length == 0 || 2 * length > ecc_len {
        return false;
    }
    // Chien search: position p ↔ X = α^(n−1−p); a root of Λ at X^−1.
    let mut positions = Vec::new();
    for p in 0..n {
        let power = n - 1 - p;
        let inverse = field.exp(255 - power % 255);
        if field.eval_low(&locator, inverse) == 0 {
            positions.push(p);
        }
    }
    if positions.len() != length {
        return false;
    }
    // Ω = S·Λ mod x^ecc_len; Forney (first root α^0): e = X·Ω(X⁻¹)/Λ'(X⁻¹).
    let mut omega = vec![0_u8; ecc_len];
    for (i, s) in syndromes.iter().enumerate() {
        for (j, l) in locator.iter().enumerate() {
            if let Some(slot) = omega.get_mut(i + j) {
                *slot ^= field.mul(*s, *l);
            }
        }
    }
    let derivative: Vec<u8> = locator
        .iter()
        .enumerate()
        .skip(1)
        .map(|(i, c)| if i % 2 == 1 { *c } else { 0 })
        .collect();
    for p in positions {
        let x = field.exp(n - 1 - p);
        let inverse = field.inverse(x);
        let denominator = field.eval_low(&derivative, inverse);
        if denominator == 0 {
            return false;
        }
        let magnitude = field.mul(x, field.div(field.eval_low(&omega, inverse), denominator));
        if let Some(byte) = block.get_mut(p) {
            *byte ^= magnitude;
        }
    }
    (0..ecc_len).all(|j| {
        let x = field.exp(j);
        block.iter().fold(0, |acc, byte| field.mul(acc, x) ^ byte) == 0
    })
}

/// De-interleaves and corrects the codewords; returns the data codewords in order.
fn correct(codewords: &[u8], version: usize, ecl: usize) -> Option<Vec<u8>> {
    let num_blocks = usize::from(*NUM_ERROR_CORRECTION_BLOCKS.get(ecl)?.get(version)?);
    let ecc_len = usize::from(*ECC_CODEWORDS_PER_BLOCK.get(ecl)?.get(version)?);
    let raw = raw_data_modules(version) / 8;
    if codewords.len() != raw || num_blocks == 0 {
        return None;
    }
    let short_blocks = num_blocks - raw % num_blocks;
    let short_len = raw / num_blocks;
    let mut blocks = vec![vec![0_u8; short_len + 1]; num_blocks];
    let mut source = codewords.iter();
    for i in 0..=short_len {
        for (j, block) in blocks.iter_mut().enumerate() {
            if i != short_len - ecc_len || j >= short_blocks {
                *block.get_mut(i)? = *source.next()?;
            }
        }
    }
    let field = Field::new();
    let mut data = Vec::new();
    for (j, mut block) in blocks.into_iter().enumerate() {
        let data_len = short_len - ecc_len + usize::from(j >= short_blocks);
        if j < short_blocks {
            block.remove(short_len - ecc_len);
        }
        if !rs_correct(&field, &mut block, ecc_len) {
            return None;
        }
        data.extend_from_slice(block.get(..data_len)?);
    }
    Some(data)
}

struct BitReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl BitReader<'_> {
    fn read(&mut self, count: usize) -> Option<u32> {
        if count > 32 || self.position + count > self.bytes.len() * 8 {
            return None;
        }
        let mut value = 0_u32;
        for _ in 0..count {
            let byte = self.bytes.get(self.position >> 3)?;
            value = (value << 1) | u32::from((byte >> (7 - (self.position & 7))) & 1);
            self.position += 1;
        }
        Some(value)
    }

    fn remaining(&self) -> usize {
        self.bytes.len() * 8 - self.position
    }
}

const ALPHANUMERIC: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

/// Parses the segments of the data codewords into bytes.
fn parse_segments(data: &[u8], version: usize) -> Option<Vec<u8>> {
    // Character-count widths (numeric, alphanumeric, byte) of the version group.
    let (numeric_bits, alnum_bits, byte_bits) = if version <= 9 {
        (10, 9, 8)
    } else if version <= 26 {
        (12, 11, 16)
    } else {
        (14, 13, 16)
    };
    let mut reader = BitReader {
        bytes: data,
        position: 0,
    };
    let mut out = Vec::new();
    while reader.remaining() >= 4 {
        let mode = reader.read(4)?;
        match mode {
            0 => break,
            // ECI: the assignment number (1, 2 or 3 bytes) is skipped; the bytes stay as they are.
            7 => {
                let first = reader.read(8)?;
                if first & 0x80 != 0 {
                    reader.read(if first & 0x40 == 0 { 8 } else { 16 })?;
                }
            }
            1 => {
                let count = usize::try_from(reader.read(numeric_bits)?).ok()?;
                let mut left = count;
                while left >= 3 {
                    let value = reader.read(10)?;
                    if value > 999 {
                        return None;
                    }
                    out.extend_from_slice(format!("{value:03}").as_bytes());
                    left -= 3;
                }
                if left == 2 {
                    let value = reader.read(7)?;
                    if value > 99 {
                        return None;
                    }
                    out.extend_from_slice(format!("{value:02}").as_bytes());
                } else if left == 1 {
                    let value = reader.read(4)?;
                    if value > 9 {
                        return None;
                    }
                    out.extend_from_slice(format!("{value}").as_bytes());
                }
            }
            2 => {
                let count = usize::try_from(reader.read(alnum_bits)?).ok()?;
                let symbol = |index: u32| ALPHANUMERIC.get(usize::try_from(index).ok()?).copied();
                let mut left = count;
                while left >= 2 {
                    let value = reader.read(11)?;
                    out.push(symbol(value / 45)?);
                    out.push(symbol(value % 45)?);
                    left -= 2;
                }
                if left == 1 {
                    out.push(symbol(reader.read(6)?)?);
                }
            }
            4 => {
                let count = usize::try_from(reader.read(byte_bits)?).ok()?;
                for _ in 0..count {
                    out.push(u8::try_from(reader.read(8)?).ok()?);
                }
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Decodes a sampled grid.
fn decode_grid(grid: &Grid) -> Option<Vec<u8>> {
    let version = grid.version()?;
    let (ecl_bits, mask) = grid.format()?;
    let codewords = read_codewords(grid, version, mask);
    let data = correct(&codewords, version, ecl_row(ecl_bits))?;
    parse_segments(&data, version)
}

fn try_bits(bits: &Bits) -> Option<Vec<u8>> {
    let candidates = find_candidates(bits);
    if candidates.len() < 3 {
        return None;
    }
    for ([top_left, top_right, bottom_left], _) in triples(&candidates) {
        let module = candidates.iter().map(|c| c.module).sum::<f64>() / fl(candidates.len());
        let module = {
            // The finders of this triple decide the module size.
            let near = |p: Point| {
                candidates
                    .iter()
                    .min_by(|a, b| a.center.distance(p).total_cmp(&b.center.distance(p)))
                    .map_or(module, |c| c.module)
            };
            (near(top_left) + near(top_right) + near(bottom_left)) / 3.0
        };
        let span = f64::midpoint(top_left.distance(top_right), top_left.distance(bottom_left));
        let Some(estimate) = round_small(span / module + 7.0) else {
            continue;
        };
        let base = match estimate % 4 {
            0 => estimate + 1,
            2 => estimate.saturating_sub(1),
            3 => estimate.saturating_sub(2),
            _ => estimate,
        };
        for size in [
            base,
            base + 4,
            base.saturating_sub(4),
            base + 8,
            base.saturating_sub(8),
        ] {
            if !(21..=177).contains(&size) || (size - 17) % 4 != 0 {
                continue;
            }
            let far = fl(size) - 3.5;
            let bottom_right = Point {
                x: top_right.x + bottom_left.x - top_left.x,
                y: top_right.y + bottom_left.y - top_left.y,
            };
            let module_points = [
                Point { x: 3.5, y: 3.5 },
                Point { x: far, y: 3.5 },
                Point { x: far, y: far },
                Point { x: 3.5, y: far },
            ];
            let affine = Transform::quad_to_quad(
                module_points,
                [top_left, top_right, bottom_right, bottom_left],
            );
            let mut transforms = vec![affine];
            if size >= 25
                && let Some(alignment) = find_alignment(bits, &affine, size)
            {
                let near = fl(size) - 6.5;
                transforms.insert(
                    0,
                    Transform::quad_to_quad(
                        [
                            Point { x: 3.5, y: 3.5 },
                            Point { x: far, y: 3.5 },
                            Point { x: near, y: near },
                            Point { x: 3.5, y: far },
                        ],
                        [top_left, top_right, alignment, bottom_left],
                    ),
                );
            }
            for transform in transforms {
                let Some(dark) = sample(bits, &transform, size) else {
                    continue;
                };
                let grid = Grid { size, dark };
                if let Some(bytes) = decode_grid(&grid) {
                    return Some(bytes);
                }
            }
        }
    }
    None
}

/// Decodes the first readable QR code in `gray`: the payload bytes.
#[must_use]
pub fn decode(gray: &Gray) -> Option<Vec<u8>> {
    let global = binarize_global(gray);
    if let Some(bytes) = try_bits(&global) {
        return Some(bytes);
    }
    let local = binarize_local(gray);
    if let Some(bytes) = try_bits(&local) {
        return Some(bytes);
    }
    // Light-on-dark codes (dark-mode pages).
    try_bits(&global.inverted()).or_else(|| try_bits(&local.inverted()))
}

/// [`decode`] of BGRA pixels, as UTF-8 text.
#[must_use]
pub fn decode_bgra_text(width: usize, height: usize, pixels: &[u8]) -> Option<String> {
    let gray = Gray::from_bgra(width, height, pixels)?;
    String::from_utf8(decode(&gray)?).ok()
}
