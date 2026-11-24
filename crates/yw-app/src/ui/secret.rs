//! Secret input and display windows W01–W10 (spec/04 §4, D11): the Windows half — the window
//! size, the capture decision, the window timer and paste bound, and the paint.
//!
//! The windows are custom-drawn (no OS EDIT control holds a secret); input arrives only as
//! `WM_CHAR` units into the form's `SecretField` buffers; painting uses short-lived zeroizing
//! UTF-16 copies. Ported from `archive/spec-v2.4:crates/secret-input-ui/src/recovery_native.rs`
//! (painting 342-470).
//!
//! 2026-11-20 (spec/15 §11.4 S4 P7a1): the window kinds (`SecretKind`, `CardSecretKind`), the
//! flow step (`SecretStep`) and the fixed texts (`text`, was `ui::secret_text`) moved to
//! `yw_engine::secret`; the window size in DIP stayed here ([`window_size`], was
//! `SecretKind::size`).
//!
//! 2026-11-22 (spec/15 §11.4 S4d E0a): the W08 hold (`HoldGate`, `BACKUP_ACK_HOLD_MS`; the reset
//! gate of S22 uses it too) and the displayed secret's container (`DisplaySecret`, which the
//! wallet's secret session holds until the shell verified the window's capture exclusion) moved
//! to `yw_engine::secret` unchanged, its redacted `Debug` included. `Submission` stayed here until
//! the wallet moved (S4d E1): a frozen helper named it by this path. 2026-11-23 (S4d E1): it is
//! `yw_engine::secret::Submission` (unchanged, its redacted `Debug` included; the wallet's
//! `on_submit` takes it).
//!
//! 2026-11-24 (spec/15 §11.4 S5-7; spec/04 §4.3): the form takes neutral events,
//! `SecretForm::on_key` a `yw_engine::secret::input::SecretKey` and `SecretForm::on_pointer` a
//! `SecretPointer`, which the shell builds with `ui::secret_input` (the only place that names a
//! virtual-key code or hit-tests pixels; source check `secret_keys_are_mapped_only_by_the_mapper`).
//! Before, `on_char(unit)`, `on_key(vk, ctrl, shift, alt)` and `on_mouse_down`/`on_mouse_move`/
//! `on_mouse_up(x, y)` took the Windows values and the form kept the hit rects of its last paint
//! (`Layout`); now the paint returns them as `ui::secret_input::HitLayout`, which the shell keeps
//! in its window record. The buttons are `SecretButton` (was the private `Button`).
//!
//! 2026-11-24 (spec/15 §11.4 S5-8; spec/04 §4.2, §4.7, §4.8): the form — its state, its events,
//! `FormAction`, `WordMark` and the window texts it builds — moved to
//! `yw_engine::secret::form::SecretForm` with its state tests; the shell still owns the instance
//! (`App::secret`). What stayed here is Windows: [`window_size`], [`capture_decision`], the timer
//! and the paste bound, and the paint, now [`paint_form`] over the form's read-only view
//! `SecretView` (before, `SecretForm::paint` and the form's private paint methods, the same
//! drawing in the same order). The shell never names the displayed secret: a display window's form
//! is built by `Wallet::open_display_window` and handed to the shell's `DisplayHost`.

use yw_core::lang::Lang;
use yw_core::secret::Zeroizing;
use yw_engine::secret::form::{SecretView, WordMark};
use yw_engine::secret::input::SecretButton;
use yw_engine::secret::{BACKUP_ACK_HOLD_MS, CardSecretKind, SecretKind, SecretStep, text};
use yw_win::ui::{DrawFlags, PaintDc, Rect, scale};

use crate::ui::secret_input::HitLayout;
use crate::ui::theme::{self, Fonts, wide};
use yw_engine::errors::ErrorCode;

/// Clipboard read bound.
pub const PASTE_MAX_UTF16_UNITS: usize = 4_096;
/// Window timer id and period.
pub const SECRET_TIMER_ID: usize = 1;
/// Timer period (hold progress, timeouts).
pub const SECRET_TIMER_MS: u32 = 50;

/// A secret window's client size in DIP (spec/04 §1.7: 640×480, W08/W09 820×680). 2026-11-20
/// (S4 P7a1): was `SecretKind::size`; the kind moved to `yw_engine::secret`, its pixels stay here.
#[must_use]
pub const fn window_size(kind: SecretKind) -> (i32, i32) {
    match kind {
        SecretKind::ShowMnemonic { .. } | SecretKind::ShowKey => (820, 680),
        SecretKind::Mnemonic => (720, 600),
        // W07 also carries the T-IMPORTED-KEY backup warning.
        SecretKind::Backup { .. }
        | SecretKind::ChangePassword
        | SecretKind::PrivateKey { .. }
        | SecretKind::CardSecret(CardSecretKind::ChangePin(_) | CardSecretKind::SetPins) => {
            (640, 560)
        }
        _ => (640, 480),
    }
}

/// What the app does after `create_window` for a secret window (spec/04 §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureDecision {
    /// Attach the secret state and show; `warning` = T-CAPTURE-WARN banner, `보기` disabled.
    Show {
        /// Exclusion not in effect.
        warning: bool,
    },
    /// Do not show the secret; wipe it and report E-SEC-001 on the main window.
    Refuse(ErrorCode),
}

/// Maps the creation result (`Ok(excluded)` or `Err` = `CaptureExclusionFailed`) to the app
/// decision. A `Required` (display) window can only come back excluded or as an error.
#[must_use]
pub const fn capture_decision(kind: SecretKind, created: Result<bool, ()>) -> CaptureDecision {
    match (kind.is_display(), created) {
        (_, Err(())) | (true, Ok(false)) => CaptureDecision::Refuse(ErrorCode::Sec001),
        (_, Ok(true)) => CaptureDecision::Show { warning: false },
        (false, Ok(false)) => CaptureDecision::Show { warning: true },
    }
}

/// The two parts of W01/W04's status line for the form's password checks
/// (`SecretView::password_checks`). A failed condition names what is wrong, not the rule with a ✗
/// before it ("✗ 두 칸이 같음" read as "being the same is wrong", 2026-11-12). The fields take only
/// 0x20–0x7E and at most 128 characters, so the rule fails only by being short.
const fn password_status(
    lang: Lang,
    rule: Option<bool>,
    same: Option<bool>,
) -> [(&'static str, yw_win::ui::Color); 2] {
    [
        match rule {
            Some(true) => (text::PW_RULE_OK.get(lang), theme::SUCCESS_TEXT),
            Some(false) => (text::PW_RULE_SHORT.get(lang), theme::DANGER_TEXT),
            None => (text::PW_RULE_EMPTY.get(lang), theme::MUTED),
        },
        match same {
            Some(true) => (text::PW_SAME.get(lang), theme::SUCCESS_TEXT),
            Some(false) => (text::PW_DIFFERENT.get(lang), theme::DANGER_TEXT),
            None => (text::PW_AGAIN.get(lang), theme::MUTED),
        },
    ]
}

/// Draws the flow name, `n/{steps}단계` and the step dots of a secret window; returns the new y.
#[expect(clippy::too_many_arguments, reason = "plain layout helpers")]
fn paint_steps(
    dc: &mut PaintDc<'_>,
    fonts: &Fonts,
    lang: Lang,
    step: SecretStep,
    margin: i32,
    y: i32,
    width: i32,
    px: &dyn Fn(i32) -> i32,
) -> i32 {
    dc.select_font(&fonts.caption);
    dc.set_text_color(theme::MUTED);
    dc.draw_text(
        &wide(&text::STEPS.fill(
            lang,
            [
                step.title(lang),
                &step.current.to_string(),
                &step.labels(lang).len().to_string(),
            ],
        )),
        Rect::new(margin, y, width, px(18)),
        DrawFlags::LINE,
    );
    let top = y.saturating_add(px(22));
    let dot = px(20);
    let count = i32::try_from(step.labels(lang).len()).unwrap_or(1).max(1);
    let column = width / count;
    // Five labels share the width: the caption font keeps each on its line.
    let small = step.labels(lang).len() > 3;
    for (index, label) in step.labels(lang).iter().enumerate() {
        let number = index.saturating_add(1);
        let x = margin.saturating_add(column.saturating_mul(i32::try_from(index).unwrap_or(0)));
        let reached = number <= step.current;
        dc.ellipse(
            Rect::new(x, top, dot, dot),
            if reached {
                theme::PRIMARY_BG
            } else {
                theme::CARD
            },
            if reached {
                theme::PRIMARY_BG
            } else {
                theme::BORDER
            },
        );
        dc.select_font(&fonts.caption);
        dc.set_text_color(if reached {
            theme::PRIMARY_TEXT
        } else {
            theme::MUTED
        });
        let mark = if number < step.current {
            "✓".to_owned()
        } else {
            number.to_string()
        };
        dc.draw_text(&wide(&mark), Rect::new(x, top, dot, dot), DrawFlags::CENTER);
        dc.select_font(if small {
            &fonts.caption
        } else if number == step.current {
            &fonts.body_bold
        } else {
            &fonts.body
        });
        dc.set_text_color(if reached { theme::TEXT } else { theme::MUTED });
        dc.draw_text(
            &wide(label),
            Rect::new(
                x.saturating_add(dot).saturating_add(px(8)),
                top,
                column.saturating_sub(dot).saturating_sub(px(12)),
                dot,
            ),
            DrawFlags::LINE,
        );
    }
    top.saturating_add(dot).saturating_add(px(14))
}

/// The lines between the content and the messages (2026-11-10): W01/W04's two password
/// conditions, W10's word that is not in the list, W08's countdown on a first display.
/// Returns the new y.
#[expect(clippy::too_many_arguments, reason = "plain layout helpers")]
fn paint_status(
    view: &SecretView<'_>,
    dc: &mut PaintDc<'_>,
    fonts: &Fonts,
    margin: i32,
    mut y: i32,
    width: i32,
    px: impl Fn(i32) -> i32,
    now_ms: u64,
) -> i32 {
    dc.select_font(&fonts.body);
    if let Some((rule, same)) = view.password_checks() {
        let [(rule, rule_color), (same, same_color)] = password_status(view.lang(), rule, same);
        let mut x = margin;
        for (text, color) in [
            (rule, rule_color),
            (" · ", theme::MUTED),
            (same, same_color),
        ] {
            let units = wide(text);
            let (_, text_w) = dc.measure(&units, i32::MAX);
            dc.set_text_color(color);
            dc.draw_text(
                &units,
                Rect::new(x, y, text_w.saturating_add(px(2)), px(22)),
                DrawFlags::LINE,
            );
            x = x.saturating_add(text_w);
        }
        y = y.saturating_add(px(26));
    }
    let mut lines: Vec<(String, yw_win::ui::Color)> = Vec::new();
    if let Some(position) = view.unlisted_position() {
        lines.push((
            text::UNLISTED_WORD.fill(view.lang(), [&position.to_string()]),
            theme::DANGER_TEXT,
        ));
    }
    if let Some(line) = view.countdown_line(now_ms) {
        lines.push((line, theme::MUTED));
    }
    for (line, color) in lines {
        let units = wide(&line);
        dc.set_text_color(color);
        let height = dc.measure_wrapped(&units, width, DrawFlags::WRAP);
        dc.draw_text(&units, Rect::new(margin, y, width, height), DrawFlags::WRAP);
        y = y.saturating_add(height).saturating_add(px(4));
    }
    y
}

/// Paints the window from the form's read-only view and returns what it drew where, for the
/// shell's hit-testing (2026-11-24, S5-7: before, the form kept it). 2026-11-24 (S5-8): a free fn
/// over `SecretView`, the only reader of it (source check
/// `the_secret_form_is_read_only_by_its_paint_and_copy`); before, `SecretForm::paint` and its
/// `layout_and_paint`, the same drawing.
#[expect(
    clippy::too_many_lines,
    reason = "one linear paint pass for every window kind"
)]
#[must_use]
pub fn paint_form(
    view: &SecretView<'_>,
    dc: &mut PaintDc<'_>,
    client: Rect,
    fonts: &Fonts,
    dpi: u32,
    now_ms: u64,
) -> HitLayout {
    let px = |dip: i32| scale(dip, dpi);
    let margin = px(theme::SPACE_XL);
    let width = client
        .w
        .saturating_sub(margin.saturating_mul(2))
        .max(px(100));
    let mut y = px(theme::SPACE_L);
    let mut layout = HitLayout::default();
    let lang = view.lang();
    dc.fill_rect(client, theme::BG);

    if !view.capture_excluded() {
        let warning = wide(text::CAPTURE_WARN.get(lang));
        dc.select_font(&fonts.body_bold);
        let height = dc.measure_wrapped(&warning, width.saturating_sub(px(20)), DrawFlags::WRAP);
        let banner = Rect::new(margin, y, width, height.saturating_add(px(20)));
        dc.round_rect(
            banner,
            px(theme::RADIUS_CONTROL),
            theme::DANGER_BG,
            theme::DANGER_ACCENT,
        );
        dc.set_text_color(theme::DANGER_TEXT);
        dc.draw_text(&warning, banner.inset(px(10)), DrawFlags::WRAP);
        y = banner.bottom().saturating_add(px(12));
    }

    if let Some(step) = view.step() {
        y = paint_steps(dc, fonts, lang, step, margin, y, width, &px);
    }

    dc.select_font(&fonts.title);
    dc.set_text_color(theme::TEXT);
    let title = wide(view.kind().title(lang));
    let title_h = dc.measure_wrapped(&title, width, DrawFlags::WRAP);
    dc.draw_text(
        &title,
        Rect::new(margin, y, width, title_h),
        DrawFlags::WRAP,
    );
    y = y.saturating_add(title_h).saturating_add(px(6));

    dc.select_font(&fonts.body);
    dc.set_text_color(theme::MUTED);
    for paragraph in view.intro().iter().chain(view.details()) {
        let units = wide(paragraph);
        let height = dc.measure_wrapped(&units, width, DrawFlags::WRAP);
        dc.draw_text(&units, Rect::new(margin, y, width, height), DrawFlags::WRAP);
        y = y.saturating_add(height).saturating_add(px(8));
    }

    let buttons_h = px(36);
    let buttons_y = client
        .h
        .saturating_sub(px(theme::SPACE_L))
        .saturating_sub(buttons_h);
    // The content card between the header and the buttons.
    let card = Rect::new(
        margin,
        y.saturating_add(px(4)),
        width,
        buttons_y
            .saturating_sub(px(theme::SPACE_M))
            .saturating_sub(y.saturating_add(px(4)))
            .max(px(40)),
    );
    dc.round_rect(
        card,
        px(theme::RADIUS_CARD),
        theme::CARD,
        theme::CARD_BORDER,
    );
    let content_top = card.y;
    let inner_x = card.x.saturating_add(px(theme::SPACE_L));
    let inner_w = card.w.saturating_sub(px(theme::SPACE_L).saturating_mul(2));
    y = card.y.saturating_add(px(theme::SPACE_L));

    if let Some(shown) = view.shown_text() {
        y = paint_display(view, dc, shown, fonts, inner_x, y, inner_w, px);
    } else if view.kind() == SecretKind::Mnemonic {
        y = paint_mnemonic_grid(view, dc, fonts, inner_x, y, inner_w, px, &mut layout);
    } else {
        y = paint_fields(
            view,
            dc,
            fonts,
            inner_x,
            y,
            inner_w,
            px,
            &mut layout,
            now_ms,
        );
    }

    if let Some((label, checked)) = view.checkbox() {
        let box_rect = Rect::new(inner_x, y, px(18), px(18));
        dc.round_rect(
            box_rect,
            px(3),
            if checked { theme::FOCUS } else { theme::CARD },
            if checked { theme::FOCUS } else { theme::BORDER },
        );
        if checked {
            dc.select_font(&fonts.body_bold);
            dc.set_text_color(theme::PRIMARY_TEXT);
            dc.draw_text(&wide("✓"), box_rect, DrawFlags::CENTER);
        }
        dc.select_font(&fonts.body);
        dc.set_text_color(theme::TEXT);
        let label_rect = Rect::new(
            inner_x.saturating_add(px(26)),
            y.saturating_sub(px(2)),
            inner_w,
            px(22),
        );
        dc.draw_text(&wide(label), label_rect, DrawFlags::LINE);
        layout.buttons.push((
            SecretButton::Checkbox,
            Rect::new(inner_x, y, inner_w / 2, px(20)),
        ));
        y = y.saturating_add(px(26));
        if checked && let Some(note) = view.note() {
            dc.set_text_color(theme::MUTED);
            dc.select_font(&fonts.caption);
            let units = wide(note);
            let height = dc.measure_wrapped(&units, inner_w, DrawFlags::WRAP);
            dc.draw_text(
                &units,
                Rect::new(inner_x, y, inner_w, height),
                DrawFlags::WRAP,
            );
            y = y.saturating_add(height).saturating_add(px(6));
        }
    }

    y = paint_status(view, dc, fonts, inner_x, y, inner_w, px, now_ms);
    dc.select_font(&fonts.body);
    for (message, color) in [
        (view.error(), theme::DANGER_TEXT),
        (view.transient(), theme::DANGER_TEXT),
        (view.info(), theme::MUTED),
        (
            view.busy().then_some(text::CHECKING.get(lang)),
            theme::MUTED,
        ),
    ] {
        if let Some(message) = message {
            let units = wide(message);
            dc.set_text_color(color);
            let height = dc.measure_wrapped(&units, inner_w, DrawFlags::WRAP);
            dc.draw_text(
                &units,
                Rect::new(inner_x, y, inner_w, height),
                DrawFlags::WRAP,
            );
            y = y.saturating_add(height).saturating_add(px(4));
        }
    }

    paint_buttons(
        view,
        dc,
        fonts,
        client,
        margin,
        buttons_y,
        buttons_h,
        px,
        &mut layout,
        now_ms,
    );

    if view.masked() {
        dc.round_rect(
            card,
            px(theme::RADIUS_CARD),
            theme::CARD,
            theme::CARD_BORDER,
        );
        dc.set_text_color(theme::MUTED);
        dc.select_font(&fonts.body);
        dc.draw_text(
            &wide(text::MASKED.get(lang)),
            card.inset(margin),
            DrawFlags::WRAP_CENTER,
        );
        layout.fields.clear();
        let _ = content_top;
    }
    layout
}

/// W08/W09: the displayed secret `shown` (borrowed from the view, drawn through short-lived
/// zeroizing copies), W08's first address and passphrase note.
#[expect(clippy::too_many_arguments, reason = "plain layout helpers")]
fn paint_display(
    view: &SecretView<'_>,
    dc: &mut PaintDc<'_>,
    shown: &str,
    fonts: &Fonts,
    margin: i32,
    mut y: i32,
    width: i32,
    px: impl Fn(i32) -> i32,
) -> i32 {
    dc.set_text_color(theme::TEXT);
    if matches!(view.kind(), SecretKind::ShowKey) {
        dc.select_font(&fonts.mono_large);
        let text = shown;
        // A Solana keypair (up to 88 characters, no spaces) does not fit one line: paint it
        // in lines of 44 (the copied text is unchanged).
        let mut units = Zeroizing::new(Vec::with_capacity(text.len().saturating_add(2)));
        for (index, unit) in text.encode_utf16().enumerate() {
            if text.len() > 64 && index > 0 && index % 44 == 0 {
                units.push(0x000A);
            }
            units.push(unit);
        }
        let box_rect = Rect::new(margin, y, width, px(80));
        dc.round_rect(box_rect, px(6), theme::BG, theme::CARD_BORDER);
        dc.draw_text(&units, box_rect.inset(px(12)), DrawFlags::WRAP);
        return box_rect.bottom().saturating_add(px(12));
    }
    let words: Vec<&str> = shown.split(' ').collect();
    let rows = words.len().div_ceil(3).max(1);
    let cell_h = px(32);
    let col_w = width / 3;
    let grid_h = cell_h.saturating_mul(i32::try_from(rows).unwrap_or(8));
    dc.round_rect(
        Rect::new(margin, y, width, grid_h.saturating_add(px(12))),
        px(6),
        theme::BG,
        theme::CARD_BORDER,
    );
    for (index, word) in words.iter().enumerate() {
        let column = index / rows;
        let row = index % rows;
        let cell = Rect::new(
            margin
                .saturating_add(px(14))
                .saturating_add(col_w.saturating_mul(i32::try_from(column).unwrap_or(0))),
            y.saturating_add(px(6))
                .saturating_add(cell_h.saturating_mul(i32::try_from(row).unwrap_or(0))),
            col_w.saturating_sub(px(14)),
            cell_h,
        );
        dc.select_font(&fonts.mono);
        dc.set_text_color(theme::MUTED);
        let number = wide(&format!("{:>2}.", index.saturating_add(1)));
        dc.draw_text(
            &number,
            Rect::new(cell.x, cell.y, px(34), cell.h),
            DrawFlags::LINE,
        );
        dc.select_font(&fonts.mono_large);
        dc.set_text_color(theme::TEXT);
        let mut units = Zeroizing::new(Vec::with_capacity(16));
        units.extend(word.encode_utf16());
        dc.draw_text(
            &units,
            Rect::new(
                cell.x.saturating_add(px(36)),
                cell.y,
                cell.w.saturating_sub(px(36)),
                cell.h,
            ),
            DrawFlags::LINE,
        );
    }
    y = y.saturating_add(grid_h).saturating_add(px(24));
    if let Some(address) = view.shown_address() {
        dc.select_font(&fonts.body_bold);
        dc.set_text_color(theme::TEXT);
        dc.draw_text(
            &wide(text::FIRST_ADDRESS.get(view.lang())),
            Rect::new(margin, y, width, px(22)),
            DrawFlags::LINE,
        );
        y = y.saturating_add(px(26));
        // Whole, its ends emphasized like every address (2026-11-12, spec/04 §3.3).
        let shown = yw_core::evm::address::parse_address(address)
            .map_or_else(|_| address.to_owned(), yw_core::evm::Address::to_checksum);
        let rect = Rect::new(margin, y, width, px(26));
        let spans = yw_engine::screen::address::own_address_spans(
            &shown,
            yw_engine::screen::address::AddressKind::Evm,
            false,
        );
        if !crate::ui::theme::paint_spans(dc, fonts, &spans, rect, theme::TEXT, theme::FOCUS) {
            dc.select_font(&fonts.mono_large);
            dc.draw_text(&wide(&shown), rect, DrawFlags::LINE);
        }
        y = y.saturating_add(px(34));
    }
    if view.shown_passphrase_note() {
        dc.select_font(&fonts.body);
        dc.set_text_color(theme::WARN_TEXT);
        let note = wide(text::PASSPHRASE_REVEAL_NOTE.get(view.lang()));
        let height = dc.measure_wrapped(&note, width, DrawFlags::WRAP);
        dc.draw_text(&note, Rect::new(margin, y, width, height), DrawFlags::WRAP);
        y = y.saturating_add(height).saturating_add(px(6));
    }
    y
}

#[expect(clippy::too_many_arguments, reason = "plain layout helpers")]
fn paint_mnemonic_grid(
    view: &SecretView<'_>,
    dc: &mut PaintDc<'_>,
    fonts: &Fonts,
    margin: i32,
    y: i32,
    width: i32,
    px: impl Fn(i32) -> i32,
    layout: &mut HitLayout,
) -> i32 {
    let Some(slot) = view.first_field() else {
        return y;
    };
    let words = slot.words();
    let trailing_space = slot.ends_with_space();
    let typing = if trailing_space || words.is_empty() {
        words.len()
    } else {
        words.len().saturating_sub(1)
    };
    let rows = 8_usize;
    let cell_h = px(30);
    let col_w = width / 3;
    let grid = Rect::new(
        margin,
        y,
        width,
        cell_h.saturating_mul(8).saturating_add(px(12)),
    );
    dc.round_rect(grid, px(6), theme::CARD, theme::FOCUS);
    layout.fields.push(grid);
    dc.select_font(&fonts.mono);
    for index in 0..24_usize {
        let column = index / rows;
        let row = index % rows;
        let cell = Rect::new(
            margin
                .saturating_add(px(10))
                .saturating_add(col_w.saturating_mul(i32::try_from(column).unwrap_or(0))),
            y.saturating_add(px(6))
                .saturating_add(cell_h.saturating_mul(i32::try_from(row).unwrap_or(0))),
            col_w.saturating_sub(px(16)),
            cell_h.saturating_sub(px(4)),
        );
        if index == typing && index < 24 {
            dc.round_rect(cell, px(4), theme::INFO_BG, theme::FOCUS);
        }
        let word = words.get(index).copied().unwrap_or(&[]);
        let unknown =
            index < typing && !core::str::from_utf8(word).is_ok_and(yw_core::bip39::is_word);
        dc.set_text_color(if unknown {
            theme::DANGER_TEXT
        } else {
            theme::TEXT
        });
        let mut units = Zeroizing::new(Vec::with_capacity(16));
        units.extend(format!("{:>2}. ", index.saturating_add(1)).encode_utf16());
        units.extend(word.iter().map(|byte| u16::from(*byte)));
        dc.draw_text(&units, cell.inset(px(2)), DrawFlags::LINE);
    }
    let mut y = grid.bottom().saturating_add(px(6));
    dc.select_font(&fonts.body);
    dc.set_text_color(theme::MUTED);
    let count = view.word_count();
    dc.draw_text(
        &wide(&text::WORDS_TYPED.fill(
            view.lang(),
            [
                &count.to_string(),
                &slot.len().to_string(),
                &slot.limit().to_string(),
            ],
        )),
        Rect::new(margin, y, width, px(20)),
        DrawFlags::LINE,
    );
    y = y.saturating_add(px(26));
    y
}

#[expect(clippy::too_many_arguments, reason = "plain layout helpers")]
fn paint_fields(
    view: &SecretView<'_>,
    dc: &mut PaintDc<'_>,
    fonts: &Fonts,
    margin: i32,
    mut y: i32,
    width: i32,
    px: impl Fn(i32) -> i32,
    layout: &mut HitLayout,
    now_ms: u64,
) -> i32 {
    let lang = view.lang();
    let enabled = view.input_enabled(now_ms);
    for (index, slot) in view.fields().enumerate() {
        dc.select_font(&fonts.body_bold);
        dc.set_text_color(theme::TEXT);
        dc.draw_text(
            &wide(slot.label()),
            Rect::new(margin, y, width, px(22)),
            DrawFlags::LINE,
        );
        dc.select_font(&fonts.caption);
        // W10: the list verdict instead of the length (2026-11-10); other fields their length.
        let (right, color) = if matches!(view.kind(), SecretKind::Backup { .. }) {
            match view.word_mark(index) {
                WordMark::None => (String::new(), theme::MUTED),
                WordMark::Listed => (text::WORD_LISTED.get(lang).to_owned(), theme::MUTED),
                WordMark::Unlisted => {
                    (text::WORD_UNLISTED.get(lang).to_owned(), theme::DANGER_TEXT)
                }
            }
        } else {
            (format!("{}/{}", slot.len(), slot.limit()), theme::MUTED)
        };
        dc.set_text_color(color);
        dc.draw_text(
            &wide(&right),
            Rect::new(margin, y, width, px(22)),
            DrawFlags::RIGHT,
        );
        y = y.saturating_add(px(24));
        let reveal_w = if slot.masked() { px(64) } else { 0 };
        let box_w = width
            .saturating_sub(reveal_w)
            .saturating_sub(if slot.masked() { px(8) } else { 0 });
        let box_rect = Rect::new(margin, y, box_w, px(36));
        let focused = index == view.active();
        dc.round_rect(
            box_rect,
            px(4),
            if enabled {
                theme::CARD
            } else {
                theme::DISABLED_BG
            },
            if focused { theme::FOCUS } else { theme::BORDER },
        );
        if focused {
            dc.round_rect(box_rect.inset(1), px(3), theme::CARD, theme::FOCUS);
        }
        let show_plain = !slot.masked() || view.revealing() == Some(index);
        let units = slot.render_utf16(!show_plain);
        dc.select_font(if slot.masked() && !show_plain {
            &fonts.body
        } else {
            &fonts.mono
        });
        dc.set_text_color(theme::TEXT);
        dc.draw_text(&units, box_rect.inset(px(9)), DrawFlags::LINE);
        layout.fields.push(box_rect);
        if slot.masked() {
            let reveal = Rect::new(box_rect.right().saturating_add(px(8)), y, reveal_w, px(36));
            let reveal_enabled = view.capture_excluded() && enabled;
            dc.round_rect(
                reveal,
                px(theme::RADIUS_CONTROL),
                if reveal_enabled {
                    theme::CARD
                } else {
                    theme::DISABLED_BG
                },
                if reveal_enabled {
                    theme::BORDER
                } else {
                    theme::CARD_BORDER
                },
            );
            dc.select_font(&fonts.body);
            dc.set_text_color(if reveal_enabled {
                theme::TEXT
            } else {
                theme::DISABLED_TEXT
            });
            dc.draw_text(&wide(text::REVEAL.get(lang)), reveal, DrawFlags::CENTER);
            layout.buttons.push((SecretButton::Reveal(index), reveal));
        }
        y = y.saturating_add(px(48));
    }
    y
}

#[expect(clippy::too_many_arguments, reason = "plain layout helpers")]
fn paint_buttons(
    view: &SecretView<'_>,
    dc: &mut PaintDc<'_>,
    fonts: &Fonts,
    client: Rect,
    margin: i32,
    y: i32,
    height: i32,
    px: impl Fn(i32) -> i32,
    layout: &mut HitLayout,
    now_ms: u64,
) {
    let (right, left) = view.button_labels(now_ms);
    dc.select_font(&fonts.body);
    let mut x = client.w.saturating_sub(margin);
    for (button, label) in right.iter().rev() {
        let text = wide(label);
        let (_, text_w) = dc.measure(&text, i32::MAX);
        let w = text_w.saturating_add(px(36)).max(px(96));
        x = x.saturating_sub(w);
        let rect = Rect::new(x, y, w, height);
        paint_button(
            view,
            dc,
            rect,
            &text,
            *button,
            now_ms,
            px(4),
            px(theme::RADIUS_CONTROL),
        );
        layout.buttons.push((*button, rect));
        x = x.saturating_sub(px(8));
    }
    let mut x = margin;
    for (button, label) in &left {
        let text = wide(label);
        let (_, text_w) = dc.measure(&text, i32::MAX);
        let w = text_w.saturating_add(px(36)).max(px(96));
        let rect = Rect::new(x, y, w, height);
        paint_button(
            view,
            dc,
            rect,
            &text,
            *button,
            now_ms,
            px(4),
            px(theme::RADIUS_CONTROL),
        );
        layout.buttons.push((*button, rect));
        x = x.saturating_add(w).saturating_add(px(8));
    }
}

#[expect(clippy::too_many_arguments, reason = "plain paint helper")]
fn paint_button(
    view: &SecretView<'_>,
    dc: &mut PaintDc<'_>,
    rect: Rect,
    text: &[u16],
    button: SecretButton,
    now_ms: u64,
    bar: i32,
    radius: i32,
) {
    let enabled = view.button_enabled(button, now_ms);
    let primary = button == SecretButton::Primary;
    let (fill, border) = match (enabled, primary) {
        (false, true) => (
            theme::BUTTON_PRIMARY.disabled_fill,
            theme::BUTTON_PRIMARY.disabled_border,
        ),
        (false, false) => (theme::DISABLED_BG, theme::CARD_BORDER),
        (true, true) => (theme::PRIMARY_BG, theme::PRIMARY_BG),
        (true, false) => (theme::CARD, theme::BUTTON_SECONDARY.border),
    };
    dc.round_rect(rect, radius, fill, border);
    if primary && view.hold_active() {
        let done = BACKUP_ACK_HOLD_MS.saturating_sub(view.hold_remaining_ms(now_ms));
        let filled = i64::from(rect.w).saturating_mul(i64::try_from(done).unwrap_or(0)) / 2_000;
        let bar_rect = Rect::new(
            rect.x,
            rect.bottom().saturating_sub(bar),
            i32::try_from(filled).unwrap_or(0),
            bar,
        );
        dc.fill_rect(bar_rect, theme::WARN_ACCENT);
    }
    dc.set_text_color(match (enabled, primary) {
        (false, true) => theme::CARD,
        (false, false) => theme::DISABLED_TEXT,
        (true, true) => theme::PRIMARY_TEXT,
        (true, false) => theme::TEXT,
    });
    dc.draw_text(text, rect, DrawFlags::CENTER);
}

#[cfg(test)]
mod tests;
