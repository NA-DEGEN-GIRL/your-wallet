//! Chain badges (spec/04 §1.6.1): the small round mark drawn before every chain or network
//! name (tabs, network chips, send/receive titles, activity, connected sites, the S15 chain list,
//! the approval window header).
//!
//! The marks are ORIGINAL simplified drawings — a brand-like colour and a plain geometric mark or
//! initial — not the projects' logo files (trademarks): Ethereum an indigo disc with a two-piece
//! diamond, Arbitrum a navy disc with a blue hexagon and "A", Base a blue disc with a white ring,
//! BNB a yellow disc with a hollow diamond, Robinhood Chain a green disc with "R", `HyperEVM` a dark
//! teal disc with a teal "H", Solana a dark disc with three slanted bars (teal → purple), Bitcoin
//! an orange disc with "₿". A user-added chain gets a neutral disc with the first letter or digit
//! of its name, coloured from its chain id. Testnets (Sepolia, Solana devnet, Bitcoin testnet4)
//! are dimmed and carry a small white "T" disc at the lower right.
//!
//! Rendering is procedural: every mark is a list of shapes in a unit square whose signed distance
//! gives a one-pixel anti-aliased edge at any size, so a badge is crisp at 100–200 % DPI and in
//! the custom-painted approval window. [`Badge::render`] returns premultiplied `0xAARRGGBB` rows
//! (top-down) for `yw_win::ui::PaintDc::draw_argb` and owner-drawn button icons.

use yw_core::btc::BtcNetwork;
use yw_core::evm::chain;
use yw_core::sol::SolCluster;

use crate::meta::BookChain;
use crate::network::NetworkId;

/// Badge size next to body text (DIP).
pub const BADGE_DIP: i32 = 16;
/// Badge size next to a screen title (DIP).
pub const TITLE_BADGE_DIP: i32 = 20;
/// Gap between a badge and its text (DIP).
pub const BADGE_GAP_DIP: i32 = 6;

/// The mark inside the disc.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mark {
    /// Two-piece diamond (Ethereum, Sepolia, the EVM family).
    Diamond,
    /// Hexagon with "A" (Arbitrum One).
    Hexagon,
    /// White ring (Base).
    Ring,
    /// Hollow diamond (BNB Smart Chain).
    HollowDiamond,
    /// Three slanted bars (Solana).
    Bars,
    /// "₿" (Bitcoin).
    Bitcoin,
    /// One letter or digit (Robinhood "R", `HyperEVM` "H", user chains), drawn in `ink`.
    Letter(char),
}

/// A chain badge: disc colour, mark, mark colour and the testnet treatment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Badge {
    /// The mark.
    pub mark: Mark,
    /// Disc colour `0xRRGGBB`.
    pub color: u32,
    /// Mark colour `0xRRGGBB`.
    pub ink: u32,
    /// Dimmed with the "T" corner.
    pub testnet: bool,
}

const WHITE: u32 = 0x00FF_FFFF;

impl Badge {
    const fn new(mark: Mark, color: u32, ink: u32, testnet: bool) -> Self {
        Self {
            mark,
            color,
            ink,
            testnet,
        }
    }

    /// The badge of an EVM chain (`name` gives a user chain its letter).
    #[must_use]
    pub fn evm(chain_id: u64, name: &str) -> Self {
        match chain_id {
            chain::ETHEREUM_MAINNET => Self::new(Mark::Diamond, 0x0062_7EEA, WHITE, false),
            chain::SEPOLIA => Self::new(Mark::Diamond, 0x0062_7EEA, WHITE, true),
            chain::ARBITRUM_ONE => Self::new(Mark::Hexagon, 0x0021_3147, 0x0028_A0F0, false),
            chain::BASE_MAINNET => Self::new(Mark::Ring, 0x0000_52FF, WHITE, false),
            chain::BSC_MAINNET => Self::new(Mark::HollowDiamond, 0x00F0_B90B, WHITE, false),
            chain::ROBINHOOD_MAINNET => Self::new(Mark::Letter('R'), 0x0012_9E4A, WHITE, false),
            chain::HYPEREVM_MAINNET => {
                Self::new(Mark::Letter('H'), 0x000F_3D38, 0x0050_E3C2, false)
            }
            _ => Self::user_chain(chain_id, name),
        }
    }

    /// A user-added EVM chain: the first ASCII letter or digit of the name (a diamond when the
    /// name has none) on a disc coloured from the chain id.
    #[must_use]
    pub fn user_chain(chain_id: u64, name: &str) -> Self {
        let letter = name
            .chars()
            .find(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_uppercase());
        let color = hue_color(chain_id);
        match letter {
            Some(letter) => Self::new(Mark::Letter(letter), color, WHITE, false),
            None => Self::new(Mark::Diamond, color, WHITE, false),
        }
    }

    /// Hyperliquid (`HyperCore` and `HyperEVM` share the mark).
    #[must_use]
    pub const fn hyperliquid() -> Self {
        Self::new(Mark::Letter('H'), 0x000F_3D38, 0x0050_E3C2, false)
    }

    /// A Solana cluster.
    #[must_use]
    pub const fn solana(cluster: SolCluster) -> Self {
        Self::new(
            Mark::Bars,
            0x0016_1A2E,
            WHITE,
            matches!(cluster, SolCluster::Devnet),
        )
    }

    /// A Bitcoin network.
    #[must_use]
    pub const fn bitcoin(net: BtcNetwork) -> Self {
        Self::new(
            Mark::Bitcoin,
            0x00F7_931A,
            WHITE,
            matches!(net, BtcNetwork::Testnet4),
        )
    }

    /// The badge of a network (`name` for user EVM chains).
    #[must_use]
    pub fn network(network: NetworkId, name: &str) -> Self {
        match network {
            NetworkId::Eip155(chain_id) => Self::evm(chain_id, name),
            NetworkId::Solana(cluster) => Self::solana(crate::app_sol::core_cluster(cluster)),
            NetworkId::Bitcoin(net) => Self::bitcoin(crate::btc::core_network(net)),
        }
    }

    /// An address-book family (S14): EVM a slate diamond (every EVM chain), Solana, Bitcoin.
    #[must_use]
    pub const fn family(chain: BookChain) -> Self {
        match chain {
            BookChain::Evm => Self::new(Mark::Diamond, 0x005B_6478, WHITE, false),
            BookChain::Sol => Self::solana(SolCluster::Mainnet),
            BookChain::Btc => Self::bitcoin(BtcNetwork::Mainnet),
        }
    }

    /// Premultiplied `0xAARRGGBB` pixels of a `size` × `size` badge, rows top-down (`size` is
    /// clamped to 4–256).
    #[must_use]
    pub fn render(self, size: i32) -> Vec<u32> {
        let size = size.clamp(4, 256);
        let layers = self.layers();
        let scale = f64::from(size);
        let count = usize::try_from(size).unwrap_or(0);
        let mut out = Vec::with_capacity(count.saturating_mul(count));
        for row in 0..size {
            for column in 0..size {
                let point = Point {
                    x: (f64::from(column) + 0.5) / scale,
                    y: (f64::from(row) + 0.5) / scale,
                };
                let mut pixel = Rgba::default();
                for layer in &layers {
                    let coverage = (0.5 - layer.shape.distance(point) * scale).clamp(0.0, 1.0);
                    pixel = pixel.over(layer.color, coverage * layer.alpha);
                }
                out.push(pixel.pack());
            }
        }
        out
    }

    #[expect(clippy::too_many_lines, reason = "one arm per mark")]
    fn layers(self) -> Vec<Layer> {
        let disc = if self.testnet {
            mix(self.color, 0x00A0_A4AC, 0.45)
        } else {
            self.color
        };
        let ink = self.ink;
        let mut layers = vec![Layer::solid(
            Shape::Disk(Point { x: 0.5, y: 0.5 }, 0.5),
            disc,
        )];
        match self.mark {
            Mark::Diamond => {
                layers.push(Layer::solid(
                    Shape::polygon(&[(0.5, 0.15), (0.73, 0.51), (0.5, 0.63), (0.27, 0.51)]),
                    ink,
                ));
                layers.push(Layer {
                    shape: Shape::polygon(&[(0.27, 0.57), (0.5, 0.69), (0.73, 0.57), (0.5, 0.86)]),
                    color: ink,
                    alpha: 0.8,
                });
            }
            Mark::Hexagon => {
                let hexagon: Vec<(f64, f64)> = (0..6)
                    .map(|step| {
                        let angle = (f64::from(step) * 60.0 - 90.0).to_radians();
                        (0.5 + 0.36 * angle.cos(), 0.5 + 0.36 * angle.sin())
                    })
                    .collect();
                layers.push(Layer::solid(Shape::polygon(&hexagon), ink));
                glyph_layers(
                    &mut layers,
                    'A',
                    Point { x: 0.5, y: 0.5 },
                    0.34,
                    0.075,
                    WHITE,
                );
            }
            Mark::Ring => {
                layers.push(Layer::solid(
                    Shape::Ring(Point { x: 0.5, y: 0.5 }, 0.24, 0.1),
                    ink,
                ));
            }
            Mark::HollowDiamond => {
                layers.push(Layer::solid(
                    Shape::polygon(&[(0.5, 0.2), (0.8, 0.5), (0.5, 0.8), (0.2, 0.5)]),
                    ink,
                ));
                layers.push(Layer::solid(
                    Shape::polygon(&[(0.5, 0.39), (0.61, 0.5), (0.5, 0.61), (0.39, 0.5)]),
                    disc,
                ));
            }
            Mark::Bars => {
                let bars: [([(f64, f64); 4], u32); 3] = [
                    (
                        [(0.35, 0.28), (0.76, 0.28), (0.66, 0.38), (0.25, 0.38)],
                        0x0014_F1A5,
                    ),
                    (
                        [(0.25, 0.45), (0.66, 0.45), (0.76, 0.55), (0.35, 0.55)],
                        0x0058_B6F0,
                    ),
                    (
                        [(0.35, 0.62), (0.76, 0.62), (0.66, 0.72), (0.25, 0.72)],
                        0x00A2_5BFF,
                    ),
                ];
                for (points, color) in bars {
                    layers.push(Layer::solid(Shape::polygon(&points), color));
                }
            }
            Mark::Bitcoin => {
                let center = Point { x: 0.5, y: 0.5 };
                glyph_layers(&mut layers, 'B', center, 0.46, 0.085, ink);
                let ticks = [(0.44, 0.12, 0.27), (0.56, 0.12, 0.27)];
                for (x, top, bottom) in ticks {
                    for (from, to) in [(top, bottom), (1.0 - bottom, 1.0 - top)] {
                        layers.push(Layer::solid(
                            Shape::Segment(Point { x, y: from }, Point { x, y: to }, 0.07),
                            ink,
                        ));
                    }
                }
            }
            Mark::Letter(letter) => {
                if glyph(letter).is_empty() {
                    layers.push(Layer::solid(
                        Shape::Ring(Point { x: 0.5, y: 0.5 }, 0.2, 0.09),
                        ink,
                    ));
                } else {
                    glyph_layers(
                        &mut layers,
                        letter,
                        Point { x: 0.5, y: 0.5 },
                        0.46,
                        0.09,
                        ink,
                    );
                }
            }
        }
        if self.testnet {
            let corner = Point { x: 0.78, y: 0.78 };
            layers.push(Layer::solid(Shape::Disk(corner, 0.24), 0x0033_3A44));
            layers.push(Layer::solid(Shape::Disk(corner, 0.2), WHITE));
            glyph_layers(&mut layers, 'T', corner, 0.22, 0.07, 0x0033_3A44);
        }
        layers
    }
}

/// A distinct, readable disc colour for a chain id (hue from a multiplicative hash, fixed
/// saturation and lightness so white text stays legible).
fn hue_color(chain_id: u64) -> u32 {
    let hue = chain_id.wrapping_mul(2_654_435_761) % 360;
    let hue = f64::from(u16::try_from(hue).unwrap_or(0));
    let (saturation, lightness) = (0.48, 0.42);
    let chroma = (1.0 - (2.0 * lightness - 1.0_f64).abs()) * saturation;
    let sector = hue / 60.0;
    let second = chroma * (1.0 - (sector % 2.0 - 1.0).abs());
    let (red, green, blue) = match sector {
        s if s < 1.0 => (chroma, second, 0.0),
        s if s < 2.0 => (second, chroma, 0.0),
        s if s < 3.0 => (0.0, chroma, second),
        s if s < 4.0 => (0.0, second, chroma),
        s if s < 5.0 => (second, 0.0, chroma),
        _ => (chroma, 0.0, second),
    };
    let base = lightness - chroma / 2.0;
    let channel = |value: f64| u32::from(to_byte((value + base) * 255.0));
    (channel(red) << 16) | (channel(green) << 8) | channel(blue)
}

/// `a` moved `amount` (0–1) toward `b`.
fn mix(a: u32, b: u32, amount: f64) -> u32 {
    let channel = |shift: u32| {
        let left = f64::from((a >> shift) & 0xFF);
        let right = f64::from((b >> shift) & 0xFF);
        u32::from(to_byte(left + (right - left) * amount)) << shift
    };
    channel(16) | channel(8) | channel(0)
}

/// A clamped, rounded byte.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is clamped to 0..=255 and rounded first"
)]
fn to_byte(value: f64) -> u8 {
    value.clamp(0.0, 255.0).round() as u8
}

#[derive(Clone, Copy, Debug)]
struct Point {
    x: f64,
    y: f64,
}

impl Point {
    fn minus(self, other: Self) -> Self {
        Self {
            x: self.x - other.x,
            y: self.y - other.y,
        }
    }

    fn dot(self, other: Self) -> f64 {
        self.x.mul_add(other.x, self.y * other.y)
    }

    fn length(self) -> f64 {
        self.dot(self).sqrt()
    }
}

/// A shape in the unit square (y down) with its signed distance (negative inside).
#[derive(Clone, Debug)]
enum Shape {
    /// Center, radius.
    Disk(Point, f64),
    /// Center, radius, stroke width.
    Ring(Point, f64, f64),
    /// From, to, stroke width (round caps).
    Segment(Point, Point, f64),
    /// Center, radius, start and end angle (degrees, y down: 0 = right, 90 = down, swept
    /// increasing), stroke width.
    Arc(Point, f64, f64, f64, f64),
    /// A simple polygon.
    Polygon(Vec<Point>),
}

impl Shape {
    fn polygon(points: &[(f64, f64)]) -> Self {
        Self::Polygon(points.iter().map(|&(x, y)| Point { x, y }).collect())
    }

    fn distance(&self, p: Point) -> f64 {
        match self {
            Self::Disk(center, radius) => p.minus(*center).length() - radius,
            Self::Ring(center, radius, width) => {
                (p.minus(*center).length() - radius).abs() - width / 2.0
            }
            Self::Segment(from, to, width) => segment_distance(p, *from, *to) - width / 2.0,
            Self::Arc(center, radius, start, end, width) => {
                let offset = p.minus(*center);
                let angle = offset.y.atan2(offset.x).to_degrees();
                let sweep = (end - start).clamp(0.0, 360.0);
                if (angle - start).rem_euclid(360.0) <= sweep {
                    (offset.length() - radius).abs() - width / 2.0
                } else {
                    let at = |degrees: f64| {
                        let radians = degrees.to_radians();
                        Point {
                            x: radius.mul_add(radians.cos(), center.x),
                            y: radius.mul_add(radians.sin(), center.y),
                        }
                    };
                    let near = p.minus(at(*start)).length().min(p.minus(at(*end)).length());
                    near - width / 2.0
                }
            }
            Self::Polygon(points) => polygon_distance(p, points),
        }
    }
}

fn segment_distance(p: Point, from: Point, to: Point) -> f64 {
    let along = to.minus(from);
    let offset = p.minus(from);
    let length = along.dot(along);
    let t = if length > 0.0 {
        (offset.dot(along) / length).clamp(0.0, 1.0)
    } else {
        0.0
    };
    Point {
        x: offset.x - along.x * t,
        y: offset.y - along.y * t,
    }
    .length()
}

/// Signed distance to a simple polygon (even-odd inside test).
fn polygon_distance(p: Point, points: &[Point]) -> f64 {
    let Some(&first) = points.first() else {
        return f64::MAX;
    };
    let mut best = p.minus(first).dot(p.minus(first));
    let mut inside = false;
    let mut previous = *points.last().unwrap_or(&first);
    for &vertex in points {
        let edge = previous.minus(vertex);
        let offset = p.minus(vertex);
        let length = edge.dot(edge);
        let t = if length > 0.0 {
            (offset.dot(edge) / length).clamp(0.0, 1.0)
        } else {
            0.0
        };
        let nearest = Point {
            x: offset.x - edge.x * t,
            y: offset.y - edge.y * t,
        };
        best = best.min(nearest.dot(nearest));
        if (vertex.y > p.y) != (previous.y > p.y) {
            let cross =
                (previous.x - vertex.x) * (p.y - vertex.y) / (previous.y - vertex.y) + vertex.x;
            if p.x < cross {
                inside = !inside;
            }
        }
        previous = vertex;
    }
    let distance = best.sqrt();
    if inside { -distance } else { distance }
}

#[derive(Clone, Debug)]
struct Layer {
    shape: Shape,
    color: u32,
    alpha: f64,
}

impl Layer {
    const fn solid(shape: Shape, color: u32) -> Self {
        Self {
            shape,
            color,
            alpha: 1.0,
        }
    }
}

/// A premultiplied pixel being composited (0–1 channels).
#[derive(Clone, Copy, Debug, Default)]
struct Rgba {
    r: f64,
    g: f64,
    b: f64,
    a: f64,
}

impl Rgba {
    /// `color` at `alpha` over `self` (premultiplied source-over).
    fn over(self, color: u32, alpha: f64) -> Self {
        if alpha <= 0.0 {
            return self;
        }
        let channel = |shift: u32| f64::from((color >> shift) & 0xFF) / 255.0;
        let keep = 1.0 - alpha;
        Self {
            r: channel(16).mul_add(alpha, self.r * keep),
            g: channel(8).mul_add(alpha, self.g * keep),
            b: channel(0).mul_add(alpha, self.b * keep),
            a: alpha + self.a * keep,
        }
    }

    fn pack(self) -> u32 {
        let byte = |value: f64| u32::from(to_byte(value * 255.0));
        (byte(self.a) << 24) | (byte(self.r) << 16) | (byte(self.g) << 8) | byte(self.b)
    }
}

/// One stroke of a glyph on its 4 × 6 grid.
#[derive(Clone, Copy, Debug)]
enum Stroke {
    /// Line `x1 y1 x2 y2`.
    L(f64, f64, f64, f64),
    /// Arc: center `x y`, radius, start and end angle (degrees, see [`Shape::Arc`]).
    A(f64, f64, f64, f64, f64),
}

use Stroke::{A, L};

const O_SHAPE: [Stroke; 4] = [
    A(2.0, 2.0, 2.0, 180.0, 360.0),
    L(0.0, 2.0, 0.0, 4.0),
    L(4.0, 2.0, 4.0, 4.0),
    A(2.0, 4.0, 2.0, 0.0, 180.0),
];

/// A small original stroke alphabet (A–Z, 0–9) for the badge initials.
#[expect(clippy::too_many_lines, reason = "one arm per glyph")]
const fn glyph(letter: char) -> &'static [Stroke] {
    match letter {
        'A' => &[
            L(0.0, 6.0, 2.0, 0.0),
            L(2.0, 0.0, 4.0, 6.0),
            L(0.8, 3.9, 3.2, 3.9),
        ],
        'B' => &[
            L(0.0, 0.0, 0.0, 6.0),
            L(0.0, 0.0, 2.4, 0.0),
            L(0.0, 2.9, 2.6, 2.9),
            L(0.0, 6.0, 2.6, 6.0),
            A(2.4, 1.45, 1.45, 270.0, 450.0),
            A(2.6, 4.45, 1.55, 270.0, 450.0),
        ],
        'C' => &[
            A(2.0, 2.0, 2.0, 180.0, 340.0),
            L(0.0, 2.0, 0.0, 4.0),
            A(2.0, 4.0, 2.0, 20.0, 180.0),
        ],
        'D' => &[
            L(0.0, 0.0, 0.0, 6.0),
            L(0.0, 0.0, 2.0, 0.0),
            L(0.0, 6.0, 2.0, 6.0),
            A(2.0, 2.0, 2.0, 270.0, 360.0),
            L(4.0, 2.0, 4.0, 4.0),
            A(2.0, 4.0, 2.0, 0.0, 90.0),
        ],
        'E' => &[
            L(0.0, 0.0, 0.0, 6.0),
            L(0.0, 0.0, 4.0, 0.0),
            L(0.0, 3.0, 3.0, 3.0),
            L(0.0, 6.0, 4.0, 6.0),
        ],
        'F' => &[
            L(0.0, 0.0, 0.0, 6.0),
            L(0.0, 0.0, 4.0, 0.0),
            L(0.0, 3.0, 3.0, 3.0),
        ],
        'G' => &[
            A(2.0, 2.0, 2.0, 180.0, 340.0),
            L(0.0, 2.0, 0.0, 4.0),
            A(2.0, 4.0, 2.0, 0.0, 180.0),
            L(4.0, 4.0, 4.0, 3.2),
            L(4.0, 3.2, 2.2, 3.2),
        ],
        'H' => &[
            L(0.0, 0.0, 0.0, 6.0),
            L(4.0, 0.0, 4.0, 6.0),
            L(0.0, 3.0, 4.0, 3.0),
        ],
        'I' => &[
            L(2.0, 0.0, 2.0, 6.0),
            L(0.8, 0.0, 3.2, 0.0),
            L(0.8, 6.0, 3.2, 6.0),
        ],
        'J' => &[L(3.0, 0.0, 3.0, 4.5), A(1.5, 4.5, 1.5, 0.0, 180.0)],
        'K' => &[
            L(0.0, 0.0, 0.0, 6.0),
            L(4.0, 0.0, 0.0, 3.6),
            L(1.3, 2.8, 4.0, 6.0),
        ],
        'L' => &[L(0.0, 0.0, 0.0, 6.0), L(0.0, 6.0, 4.0, 6.0)],
        'M' => &[
            L(0.0, 6.0, 0.0, 0.0),
            L(0.0, 0.0, 2.0, 3.6),
            L(2.0, 3.6, 4.0, 0.0),
            L(4.0, 0.0, 4.0, 6.0),
        ],
        'N' => &[
            L(0.0, 6.0, 0.0, 0.0),
            L(0.0, 0.0, 4.0, 6.0),
            L(4.0, 6.0, 4.0, 0.0),
        ],
        'O' => &O_SHAPE,
        'P' => &[
            L(0.0, 0.0, 0.0, 6.0),
            L(0.0, 0.0, 2.3, 0.0),
            L(0.0, 3.4, 2.3, 3.4),
            A(2.3, 1.7, 1.7, 270.0, 450.0),
        ],
        'Q' => &[
            A(2.0, 2.0, 2.0, 180.0, 360.0),
            L(0.0, 2.0, 0.0, 4.0),
            L(4.0, 2.0, 4.0, 4.0),
            A(2.0, 4.0, 2.0, 0.0, 180.0),
            L(2.6, 4.6, 4.2, 6.2),
        ],
        'R' => &[
            L(0.0, 0.0, 0.0, 6.0),
            L(0.0, 0.0, 2.3, 0.0),
            L(0.0, 3.4, 2.3, 3.4),
            A(2.3, 1.7, 1.7, 270.0, 450.0),
            L(2.0, 3.4, 4.0, 6.0),
        ],
        'S' => &[
            A(2.0, 1.55, 1.55, 90.0, 330.0),
            A(2.0, 4.45, 1.55, 270.0, 510.0),
        ],
        'T' => &[L(0.0, 0.0, 4.0, 0.0), L(2.0, 0.0, 2.0, 6.0)],
        'U' => &[
            L(0.0, 0.0, 0.0, 4.0),
            L(4.0, 0.0, 4.0, 4.0),
            A(2.0, 4.0, 2.0, 0.0, 180.0),
        ],
        'V' => &[L(0.0, 0.0, 2.0, 6.0), L(2.0, 6.0, 4.0, 0.0)],
        'W' => &[
            L(0.0, 0.0, 1.0, 6.0),
            L(1.0, 6.0, 2.0, 2.4),
            L(2.0, 2.4, 3.0, 6.0),
            L(3.0, 6.0, 4.0, 0.0),
        ],
        'X' => &[L(0.0, 0.0, 4.0, 6.0), L(4.0, 0.0, 0.0, 6.0)],
        'Y' => &[
            L(0.0, 0.0, 2.0, 3.0),
            L(4.0, 0.0, 2.0, 3.0),
            L(2.0, 3.0, 2.0, 6.0),
        ],
        'Z' => &[
            L(0.0, 0.0, 4.0, 0.0),
            L(4.0, 0.0, 0.0, 6.0),
            L(0.0, 6.0, 4.0, 6.0),
        ],
        '0' => &[
            A(2.0, 2.0, 2.0, 180.0, 360.0),
            L(0.0, 2.0, 0.0, 4.0),
            L(4.0, 2.0, 4.0, 4.0),
            A(2.0, 4.0, 2.0, 0.0, 180.0),
            L(3.2, 1.2, 0.8, 4.8),
        ],
        '1' => &[
            L(2.0, 0.0, 2.0, 6.0),
            L(2.0, 0.0, 0.8, 1.2),
            L(0.8, 6.0, 3.2, 6.0),
        ],
        '2' => &[
            A(2.0, 2.0, 2.0, 180.0, 380.0),
            L(3.88, 2.68, 0.0, 6.0),
            L(0.0, 6.0, 4.0, 6.0),
        ],
        '3' => &[
            A(2.0, 1.5, 1.5, 200.0, 450.0),
            A(2.0, 4.5, 1.5, 270.0, 520.0),
        ],
        '4' => &[
            L(3.0, 6.0, 3.0, 0.0),
            L(3.0, 0.0, 0.0, 4.2),
            L(0.0, 4.2, 4.0, 4.2),
        ],
        '5' => &[
            L(4.0, 0.0, 0.4, 0.0),
            L(0.4, 0.0, 0.2, 2.9),
            A(2.0, 4.2, 1.8, 225.0, 510.0),
        ],
        '6' => &[A(2.0, 4.2, 1.8, 0.0, 360.0), L(0.2, 4.2, 2.6, 0.0)],
        '7' => &[L(0.0, 0.0, 4.0, 0.0), L(4.0, 0.0, 1.4, 6.0)],
        '8' => &[A(2.0, 1.5, 1.5, 0.0, 360.0), A(2.0, 4.4, 1.6, 0.0, 360.0)],
        '9' => &[A(2.0, 1.8, 1.8, 0.0, 360.0), L(3.8, 1.8, 1.4, 6.0)],
        _ => &[],
    }
}

/// Appends the strokes of `letter`, `height` tall (unit square) and centered on `center`.
fn glyph_layers(
    layers: &mut Vec<Layer>,
    letter: char,
    center: Point,
    height: f64,
    width: f64,
    color: u32,
) {
    let unit = height / 6.0;
    let left = center.x - unit * 2.0;
    let top = center.y - height / 2.0;
    let at = |x: f64, y: f64| Point {
        x: x.mul_add(unit, left),
        y: y.mul_add(unit, top),
    };
    for stroke in glyph(letter) {
        let shape = match *stroke {
            L(x1, y1, x2, y2) => Shape::Segment(at(x1, y1), at(x2, y2), width),
            A(x, y, radius, start, end) => Shape::Arc(at(x, y), radius * unit, start, end, width),
        };
        layers.push(Layer::solid(shape, color));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alpha(pixel: u32) -> u32 {
        pixel >> 24
    }

    #[test]
    fn badges_are_round_and_antialiased_at_every_size() {
        for size in [16, 20, 24, 32] {
            let pixels = Badge::evm(chain::ETHEREUM_MAINNET, "Ethereum").render(size);
            let side = usize::try_from(size).unwrap();
            assert_eq!(pixels.len(), side * side);
            // Corners are transparent, the center is opaque, the edge has partial coverage.
            assert_eq!(alpha(pixels[0]), 0);
            assert_eq!(alpha(pixels[side * side / 2 + side / 2]), 255);
            assert!(pixels.iter().any(|p| (1..255).contains(&alpha(*p))));
            // Premultiplied: no channel above alpha.
            for pixel in &pixels {
                let a = alpha(*pixel);
                for shift in [0, 8, 16] {
                    assert!((pixel >> shift) & 0xFF <= a, "{pixel:08x}");
                }
            }
        }
    }

    #[test]
    fn every_builtin_network_has_its_own_mark() {
        let marks = [
            Badge::evm(chain::ETHEREUM_MAINNET, ""),
            Badge::evm(chain::ARBITRUM_ONE, ""),
            Badge::evm(chain::BASE_MAINNET, ""),
            Badge::evm(chain::BSC_MAINNET, ""),
            Badge::evm(chain::ROBINHOOD_MAINNET, ""),
            Badge::evm(chain::HYPEREVM_MAINNET, ""),
            Badge::solana(SolCluster::Mainnet),
            Badge::bitcoin(BtcNetwork::Mainnet),
        ];
        let rendered: Vec<Vec<u32>> = marks.iter().map(|badge| badge.render(20)).collect();
        for (index, left) in rendered.iter().enumerate() {
            for right in rendered.iter().skip(index + 1) {
                assert_ne!(left, right);
            }
        }
        assert!(Badge::evm(chain::SEPOLIA, "Sepolia").testnet);
        assert!(Badge::solana(SolCluster::Devnet).testnet);
        assert!(Badge::bitcoin(BtcNetwork::Testnet4).testnet);
        assert_ne!(
            Badge::evm(chain::SEPOLIA, "").render(20),
            Badge::evm(chain::ETHEREUM_MAINNET, "").render(20)
        );
    }

    #[test]
    fn user_chains_get_a_letter_and_a_stable_color() {
        let badge = Badge::user_chain(10, "optimism");
        assert_eq!(badge.mark, Mark::Letter('O'));
        assert_eq!(badge, Badge::evm(10, "optimism"));
        assert_ne!(
            Badge::user_chain(10, "x").color,
            Badge::user_chain(137, "x").color
        );
        assert_eq!(Badge::user_chain(5, "체인").mark, Mark::Diamond);
        assert_eq!(Badge::user_chain(5, "체인 7").mark, Mark::Letter('7'));
        for letter in ('A'..='Z').chain('0'..='9') {
            assert!(!glyph(letter).is_empty(), "{letter}");
            let pixels = Badge::user_chain(1_234, &letter.to_string()).render(24);
            assert!(pixels.contains(&0xFFFF_FFFF), "{letter} has no ink");
        }
    }
}
