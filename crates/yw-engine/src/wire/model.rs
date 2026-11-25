//! The screen model on the wire (spec/15 §3.2, §11.3; 2026-11-25 A2-6): `{"t":"model","rev":R,
//! "items":[…]}`, one object per [`Item`] with its kind word `k`, its texts, and for each control
//! its slot `s` (its place in the model's document order, [`for_each_ctl`]) — never its
//! [`Press`](crate::cmd::Press) or [`EditField`](crate::form::EditField), which stay in the
//! engine's [`Drawn`] record, and never a credential's text (the builders keep it empty,
//! `screen::model`). The Windows-only layout facts (widths, the labels a button is sized for)
//! are not sent: the Android shell lays the list out for a narrow screen itself.
//!
//! Item words: `title`, `text`, `muted`, `help`, `subtitle`, `display`, `display_muted`, `mono`
//! (`text`), `copy` (`value`, `actions`), `list` (`title`, `note`, `value`, `dim`), `pill` (`text`,
//! `tone`), `menu` (`ctls`), `field` (`label`, `value`), `banner` (`text`, `tone`, `tag`), `gap`
//! (`dip`), `row` (`ctls`), `lrow` (`label`, `ctls`), `rule`, `qr` (`size`, `bits`: the modules
//! row by row, most significant bit first, as lowercase hex), `card` (`title`), `end`, `steps`
//! (`labels`, `current`), `bar` (`title`, `ctls`), `badged` (`badge`, `item`), `hold` (`label`,
//! `progress`, `on`).
//!
//! A control: `s`, `c` (`button`, `check`, `radio`, `edit`, `cred`), `style` (a button's), `text`,
//! `on` (enabled), `checked`, `first` (a radio's group start), `password`, `readonly`, `limit` (an
//! edit's), `badge`, `compact`, `face`, `tip` — every member present, `null` where it does not
//! apply. A plain edit whose field never goes on the wire (`super::field_on_wire`: the
//! `WalletConnect` pairing link) is sent as `cred`, with no text (2026-11-25 A2-6 review).

use yw_core::lang::Lang;
use yw_core::secret::Zeroize;
use yw_json::{Number, Object, Value};

use crate::badge::{Badge, Mark};
use crate::screen::Tone;
use crate::screen::model::{Act, Ctl, CtlKind, Face, Item, Style};

/// The deepest `badged` nesting the encoder follows (the screens wrap one text item).
const BADGED_DEPTH: u32 = 4;

/// One control of a drawn model, by slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotInfo {
    /// What it does.
    pub act: Act,
    /// Its kind.
    pub kind: CtlKind,
    /// Enabled.
    pub enabled: bool,
    /// A check box's drawn state (`None`: not a check box, or none drawn).
    pub checked: Option<bool>,
    /// The top-level item it is in.
    pub item: usize,
}

/// A model the engine handed to the shell: its revision, items and controls by slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Drawn {
    rev: u64,
    items: Vec<Item>,
    slots: Vec<SlotInfo>,
}

impl Drawn {
    /// Records `items` as model `rev`, wiped of the texts that never go on the wire first
    /// ([`scrub`]).
    #[must_use]
    pub fn new(rev: u64, mut items: Vec<Item>) -> Self {
        scrub(&mut items);
        let mut slots = Vec::new();
        for_each_ctl(&items, &mut |item, ctl| {
            slots.push(SlotInfo {
                act: ctl.act,
                kind: ctl.kind,
                enabled: ctl.enabled,
                checked: ctl.checked,
                item,
            });
        });
        Self { rev, items, slots }
    }

    /// The model's revision.
    #[must_use]
    pub const fn rev(&self) -> u64 {
        self.rev
    }

    /// The model's items.
    #[must_use]
    pub fn items(&self) -> &[Item] {
        &self.items
    }

    /// The control at `slot`.
    #[must_use]
    pub fn slot(&self, slot: u32) -> Option<&SlotInfo> {
        self.slots.get(usize::try_from(slot).ok()?)
    }

    /// The slots of the controls that do `act` (a check box's state set aside), in order.
    pub fn slots_of(&self, act: Act) -> impl Iterator<Item = u32> + '_ {
        self.slots.iter().enumerate().filter_map(move |(at, slot)| {
            let same = match (slot.act, act) {
                (Act::Press(own), Act::Press(other)) => own.same_control(other),
                (own, other) => own == other,
            };
            if same { u32::try_from(at).ok() } else { None }
        })
    }

    /// The model on the wire ([`encode_model`]).
    #[must_use]
    pub fn encode(&self, lang: Lang) -> Vec<u8> {
        encode_model(self.rev, &self.items, lang)
    }
}

/// Visits every control of `items` in document order with the index of its top-level item: an
/// item's controls in their order (a copy line's value, then its actions), items in order. The
/// slot of a control is its place in this order.
pub fn for_each_ctl(items: &[Item], visit: &mut dyn FnMut(usize, &Ctl)) {
    for (index, item) in items.iter().enumerate() {
        item_ctls(item, index, visit, BADGED_DEPTH);
    }
}

/// Wipes the text of every plain edit whose field never goes on the wire
/// (`super::field_on_wire`) in `items` (2026-11-25 A2-6 review): the drawn record keeps no copy,
/// and a rebuilt model is compared with it only after the same wipe.
pub(crate) fn scrub(items: &mut [Item]) {
    for item in items {
        scrub_item(item, BADGED_DEPTH);
    }
}

fn scrub_item(item: &mut Item, depth: u32) {
    let wipe = |ctl: &mut Ctl| {
        if matches!(ctl.act, Act::Field(field) if !super::field_on_wire(field)) {
            ctl.text.zeroize();
        }
    };
    match item {
        Item::CopyLine { value, actions } => {
            wipe(value);
            actions.iter_mut().for_each(wipe);
        }
        Item::Menu(ctls) | Item::Row(ctls) | Item::LabeledRow(_, ctls) | Item::Toolbar(_, ctls) => {
            ctls.iter_mut().for_each(wipe);
        }
        Item::Badged(_, inner) if depth > 0 => scrub_item(inner, depth - 1),
        _ => {}
    }
}

fn item_ctls(item: &Item, index: usize, visit: &mut dyn FnMut(usize, &Ctl), depth: u32) {
    match item {
        Item::CopyLine { value, actions } => {
            visit(index, value);
            for ctl in actions {
                visit(index, ctl);
            }
        }
        Item::Menu(ctls) | Item::Row(ctls) | Item::LabeledRow(_, ctls) | Item::Toolbar(_, ctls) => {
            for ctl in ctls {
                visit(index, ctl);
            }
        }
        Item::Badged(_, inner) if depth > 0 => item_ctls(inner, index, visit, depth - 1),
        _ => {}
    }
}

/// The model `items` as revision `rev` on the wire (module doc), its texts already in `lang` but
/// for the banner tags, which are looked up in it here.
#[must_use]
pub fn encode_model(rev: u64, items: &[Item], lang: Lang) -> Vec<u8> {
    let mut slot = 0_u64;
    let encoded = items
        .iter()
        .map(|item| encode_item(item, lang, &mut slot, BADGED_DEPTH))
        .collect();
    yw_json::to_vec(&object(vec![
        ("t", string("model")),
        ("rev", Value::Number(Number::from_u64(rev))),
        ("items", Value::Array(encoded)),
    ]))
}

fn object(members: Vec<(&str, Value)>) -> Value {
    Object::from_pairs(
        members
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
    .map_or(Value::Null, Value::Object)
}

fn string(text: &str) -> Value {
    Value::String(text.to_owned())
}

fn number(value: u64) -> Value {
    Value::Number(Number::from_u64(value))
}

fn optional(text: Option<&str>) -> Value {
    text.map_or(Value::Null, string)
}

fn text_item(kind: &str, text: &str) -> Value {
    object(vec![("k", string(kind)), ("text", string(text))])
}

#[expect(
    clippy::too_many_lines,
    reason = "one arm per item kind, in the order of `Item`"
)]
fn encode_item(item: &Item, lang: Lang, slot: &mut u64, depth: u32) -> Value {
    let ctls = |ctls: &[Ctl], slot: &mut u64| {
        Value::Array(ctls.iter().map(|ctl| encode_ctl(ctl, slot)).collect())
    };
    match item {
        Item::Title(text) => text_item("title", text),
        Item::Text(text) => text_item("text", text),
        Item::Muted(text) => text_item("muted", text),
        Item::Help(text) => text_item("help", text),
        Item::Subtitle(text) => text_item("subtitle", text),
        Item::Display(text) => text_item("display", text),
        Item::DisplayMuted(text) => text_item("display_muted", text),
        Item::Mono(text) => text_item("mono", text),
        Item::CopyLine { value, actions } => {
            let value = encode_ctl(value, slot);
            object(vec![
                ("k", string("copy")),
                ("value", value),
                ("actions", ctls(actions, slot)),
            ])
        }
        Item::ListRow {
            title,
            note,
            value,
            dim,
        } => object(vec![
            ("k", string("list")),
            ("title", string(title)),
            ("note", string(note)),
            ("value", string(value)),
            ("dim", Value::Bool(*dim)),
        ]),
        Item::Pill(text, tone) => object(vec![
            ("k", string("pill")),
            ("text", string(text)),
            ("tone", string(tone_word(*tone))),
        ]),
        Item::Menu(items) => object(vec![("k", string("menu")), ("ctls", ctls(items, slot))]),
        Item::Field(label, value) => object(vec![
            ("k", string("field")),
            ("label", string(label)),
            ("value", string(value)),
        ]),
        Item::Banner(text, tone) => object(vec![
            ("k", string("banner")),
            ("text", string(text)),
            ("tone", string(tone_word(*tone))),
            ("tag", optional(tone.label(lang))),
        ]),
        Item::Gap(dip) => object(vec![
            ("k", string("gap")),
            ("dip", number(u64::try_from(*dip).unwrap_or(0))),
        ]),
        Item::Row(items) => object(vec![("k", string("row")), ("ctls", ctls(items, slot))]),
        Item::LabeledRow(label, items) => object(vec![
            ("k", string("lrow")),
            ("label", string(label)),
            ("ctls", ctls(items, slot)),
        ]),
        Item::Rule => object(vec![("k", string("rule"))]),
        Item::Qr(payload) => {
            let (size, bits) = qr_bits(payload);
            object(vec![
                ("k", string("qr")),
                ("size", number(size)),
                ("bits", Value::String(bits)),
            ])
        }
        Item::CardStart(title) => object(vec![
            ("k", string("card")),
            ("title", optional(title.as_deref())),
        ]),
        Item::CardEnd => object(vec![("k", string("end"))]),
        Item::Steps(labels, current) => object(vec![
            ("k", string("steps")),
            (
                "labels",
                Value::Array(labels.iter().map(|label| string(label)).collect()),
            ),
            (
                "current",
                number(u64::try_from(*current).unwrap_or(u64::MAX)),
            ),
        ]),
        Item::Toolbar(title, items) => object(vec![
            ("k", string("bar")),
            ("title", string(title)),
            ("ctls", ctls(items, slot)),
        ]),
        Item::Badged(badge, inner) => {
            let inner = if depth > 0 {
                encode_item(inner, lang, slot, depth - 1)
            } else {
                Value::Null
            };
            object(vec![
                ("k", string("badged")),
                ("badge", encode_badge(*badge)),
                ("item", inner),
            ])
        }
        Item::Hold {
            label,
            progress,
            enabled,
        } => object(vec![
            ("k", string("hold")),
            ("label", string(label)),
            ("progress", number(u64::from(*progress))),
            ("on", Value::Bool(*enabled)),
        ]),
    }
}

fn encode_ctl(ctl: &Ctl, slot: &mut u64) -> Value {
    let at = *slot;
    *slot = slot.saturating_add(1);
    let hidden = match ctl.act {
        Act::Cred(_) => true,
        Act::Field(field) => !super::field_on_wire(field),
        Act::Press(_) => false,
    };
    let (kind, style, first, password, readonly) = match (ctl.kind, ctl.act) {
        _ if hidden => ("cred", None, None, None, None),
        (CtlKind::Button(style), _) => ("button", Some(style_word(style)), None, None, None),
        (CtlKind::Check, _) => ("check", None, None, None, None),
        (CtlKind::Radio { first }, _) => ("radio", None, Some(first), None, None),
        (CtlKind::Edit { password, readonly }, _) => {
            ("edit", None, None, Some(password), Some(readonly))
        }
    };
    let flag = |value: Option<bool>| value.map_or(Value::Null, Value::Bool);
    object(vec![
        ("s", number(at)),
        ("c", string(kind)),
        ("style", optional(style)),
        ("text", string(if hidden { "" } else { &ctl.text })),
        ("on", Value::Bool(ctl.enabled)),
        ("checked", flag(ctl.checked)),
        ("first", flag(first)),
        ("password", flag(password)),
        ("readonly", flag(readonly)),
        (
            "limit",
            ctl.limit
                .map_or(Value::Null, |limit| number(u64::from(limit))),
        ),
        ("badge", ctl.badge.map_or(Value::Null, encode_badge)),
        ("compact", Value::Bool(ctl.compact)),
        ("face", ctl.face.as_ref().map_or(Value::Null, encode_face)),
        ("tip", optional(ctl.tip.as_deref())),
    ])
}

fn encode_lines(lines: &[Vec<(String, bool)>]) -> Value {
    Value::Array(
        lines
            .iter()
            .map(|spans| {
                Value::Array(
                    spans
                        .iter()
                        .map(|(text, bold)| Value::Array(vec![string(text), Value::Bool(*bold)]))
                        .collect(),
                )
            })
            .collect(),
    )
}

fn encode_face(face: &Face) -> Value {
    match face {
        Face::Glyph(glyph) => object(vec![("f", string("glyph")), ("glyph", string(glyph))]),
        Face::Value(lines) => object(vec![("f", string("value")), ("lines", encode_lines(lines))]),
        Face::Entry(glyph) => object(vec![("f", string("entry")), ("glyph", optional(*glyph))]),
        Face::Copied(lines, note) => object(vec![
            ("f", string("copied")),
            ("lines", encode_lines(lines)),
            ("note", string(note)),
        ]),
    }
}

fn encode_badge(badge: Badge) -> Value {
    let (mark, letter) = match badge.mark {
        Mark::Diamond => ("diamond", None),
        Mark::Hexagon => ("hexagon", None),
        Mark::Ring => ("ring", None),
        Mark::HollowDiamond => ("hollow_diamond", None),
        Mark::Bars => ("bars", None),
        Mark::Bitcoin => ("bitcoin", None),
        Mark::Letter(letter) => ("letter", Some(letter.to_string())),
    };
    object(vec![
        ("mark", string(mark)),
        ("ch", letter.map_or(Value::Null, Value::String)),
        ("color", number(u64::from(badge.color))),
        ("ink", number(u64::from(badge.ink))),
        ("testnet", Value::Bool(badge.testnet)),
    ])
}

/// A tone's word on the wire.
#[must_use]
pub const fn tone_word(tone: Tone) -> &'static str {
    match tone {
        Tone::Danger => "danger",
        Tone::Warn => "warn",
        Tone::Info => "info",
        Tone::Testnet => "testnet",
        Tone::BtcMainnet => "btc_mainnet",
        Tone::BtcTestnet4 => "btc_testnet4",
        Tone::HighRisk => "high_risk",
        Tone::Blocked => "blocked",
        Tone::Success => "success",
    }
}

/// A button style's word on the wire.
#[must_use]
pub const fn style_word(style: Style) -> &'static str {
    match style {
        Style::Primary => "primary",
        Style::Secondary => "secondary",
        Style::Danger => "danger",
        Style::Link => "link",
        Style::TabOn => "tab_on",
        Style::TabOff => "tab_off",
        Style::Entry => "entry",
        Style::EntryOn => "entry_on",
    }
}

/// The modules of the QR of `payload`, row by row, most significant bit first, as lowercase hex
/// (the last byte padded with zero bits); `(0, "")` when it does not fit a symbol.
fn qr_bits(payload: &str) -> (u64, String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let Some(matrix) = crate::screen::qr::encode(payload) else {
        return (0, String::new());
    };
    let size = matrix.size();
    let mut out = String::new();
    let mut byte = 0_u8;
    let mut filled = 0_u8;
    for y in 0..size {
        for x in 0..size {
            byte = (byte << 1) | u8::from(matrix.module(x, y));
            filled += 1;
            if filled == 8 {
                out.push(char::from(HEX[usize::from(byte >> 4)]));
                out.push(char::from(HEX[usize::from(byte & 0x0f)]));
                byte = 0;
                filled = 0;
            }
        }
    }
    if filled > 0 {
        byte <<= 8 - filled;
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    (u64::try_from(size).unwrap_or(0), out)
}
