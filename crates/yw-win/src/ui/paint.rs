#![allow(unsafe_code)]
//! GDI painting (spec/01 §7.7): `PaintDc` (BeginPaint/EndPaint RAII), fonts, rectangles, colors.
//! Text is always drawn with `DT_NOPREFIX` (spec/01 §5.5).

use core::marker::PhantomData;

use windows_sys::Win32::Foundation::{HWND, RECT, SIZE};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, CLEARTYPE_QUALITY, CLIP_DEFAULT_PRECIS, CreateFontW, CreateSolidBrush,
    DEFAULT_CHARSET, DEFAULT_PITCH, DT_CALCRECT, DT_CENTER, DT_LEFT, DT_NOPREFIX, DT_RIGHT,
    DT_SINGLELINE, DT_VCENTER, DT_WORDBREAK, DeleteObject, DrawTextW, EndPaint, FF_DONTCARE,
    FW_BOLD, FW_NORMAL, FillRect, FrameRect, GetTextExtentExPointW, HDC, HFONT, HGDIOBJ,
    OUT_DEFAULT_PRECIS, PAINTSTRUCT, SelectObject, SetBkMode, SetTextColor, TRANSPARENT,
};

use crate::error::WinError;
use crate::wide::to_wide;

/// A rectangle in client pixels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    /// Left.
    pub x: i32,
    /// Top.
    pub y: i32,
    /// Width.
    pub w: i32,
    /// Height.
    pub h: i32,
}

impl Rect {
    /// Builds a rectangle.
    #[must_use]
    pub const fn new(x: i32, y: i32, w: i32, h: i32) -> Self {
        Self { x, y, w, h }
    }

    /// Whether `(px, py)` lies inside.
    #[must_use]
    pub const fn contains(&self, px: i32, py: i32) -> bool {
        px >= self.x
            && py >= self.y
            && px < self.x.saturating_add(self.w)
            && py < self.y.saturating_add(self.h)
    }

    /// The rectangle shrunk by `d` on every side (never negative).
    #[must_use]
    pub const fn inset(&self, d: i32) -> Self {
        let twice = d.saturating_mul(2);
        let w = self.w.saturating_sub(twice);
        let h = self.h.saturating_sub(twice);
        Self {
            x: self.x.saturating_add(d),
            y: self.y.saturating_add(d),
            w: if w < 0 { 0 } else { w },
            h: if h < 0 { 0 } else { h },
        }
    }

    /// Right edge.
    #[must_use]
    pub const fn right(&self) -> i32 {
        self.x.saturating_add(self.w)
    }

    /// Bottom edge.
    #[must_use]
    pub const fn bottom(&self) -> i32 {
        self.y.saturating_add(self.h)
    }

    pub(crate) const fn to_win(self) -> RECT {
        RECT {
            left: self.x,
            top: self.y,
            right: self.x.saturating_add(self.w),
            bottom: self.y.saturating_add(self.h),
        }
    }

    pub(crate) const fn from_win(rect: &RECT) -> Self {
        Self {
            x: rect.left,
            y: rect.top,
            w: rect.right.saturating_sub(rect.left),
            h: rect.bottom.saturating_sub(rect.top),
        }
    }
}

/// An RGB color `0xRRGGBB`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Color(pub u32);

impl Color {
    /// GDI `COLORREF` (`0x00BBGGRR`).
    #[must_use]
    pub const fn colorref(self) -> u32 {
        let r = (self.0 >> 16) & 0xFF;
        let g = (self.0 >> 8) & 0xFF;
        let b = self.0 & 0xFF;
        (b << 16) | (g << 8) | r
    }
}

/// `DrawTextW` format flags; `DT_NOPREFIX` is always added.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrawFlags(u32);

impl DrawFlags {
    /// Left aligned, word wrapping.
    pub const WRAP: Self = Self(DT_LEFT | DT_WORDBREAK);
    /// One line, vertically centered, left aligned.
    pub const LINE: Self = Self(DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    /// One line, centered both ways.
    pub const CENTER: Self = Self(DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    /// One line, right aligned, vertically centered.
    pub const RIGHT: Self = Self(DT_RIGHT | DT_SINGLELINE | DT_VCENTER);
    /// Word-wrapped and horizontally centered.
    pub const WRAP_CENTER: Self = Self(DT_CENTER | DT_WORDBREAK);

    const fn bits(self) -> u32 {
        self.0 | DT_NOPREFIX
    }
}

/// A GDI font sized for one DPI (`CreateFontW`, deleted on drop).
#[derive(Debug)]
pub struct Font {
    handle: HFONT,
}

impl Font {
    /// Creates `face` at `size_pt` points for `dpi`.
    ///
    /// # Errors
    ///
    /// [`WinError`] from `CreateFontW` or an invalid face name.
    pub fn create(face: &str, size_pt: u16, bold: bool, dpi: u32) -> Result<Self, WinError> {
        let wide = to_wide(face, "CreateFontW")?;
        let pixels = i64::from(size_pt)
            .saturating_mul(i64::from(dpi))
            .saturating_add(36)
            / 72;
        let height = i32::try_from(pixels)
            .map_err(|_| WinError::invalid_argument("CreateFontW"))?
            .saturating_neg();
        // SAFETY: `wide` is a NUL-terminated face name live for the call; other arguments are
        // plain values.
        let handle = unsafe {
            CreateFontW(
                height,
                0,
                0,
                0,
                i32::try_from(if bold { FW_BOLD } else { FW_NORMAL }).unwrap_or(400),
                0,
                0,
                0,
                u32::from(DEFAULT_CHARSET),
                u32::from(OUT_DEFAULT_PRECIS),
                u32::from(CLIP_DEFAULT_PRECIS),
                u32::from(CLEARTYPE_QUALITY),
                u32::from(DEFAULT_PITCH | FF_DONTCARE),
                wide.as_ptr(),
            )
        };
        if handle.is_null() {
            return Err(WinError::last("CreateFontW"));
        }
        Ok(Self { handle })
    }

    pub(crate) const fn raw(&self) -> HFONT {
        self.handle
    }
}

impl Drop for Font {
    fn drop(&mut self) {
        // SAFETY: The font was created by `CreateFontW` and is deleted exactly once. Callers
        // deselect it before drop (`PaintDc` restores the previous font).
        unsafe { DeleteObject(self.handle) };
    }
}

/// Measures `text` drawn with `font` and `flags` in a `width`-pixel box using a temporary
/// window DC (`GetDC`/`ReleaseDC`); returns `(width, height)` of the result. Used for layout
/// outside `WM_PAINT`.
pub(crate) fn measure_with(
    hwnd: HWND,
    font: &Font,
    text: &[u16],
    width: i32,
    flags: DrawFlags,
) -> (i32, i32) {
    let Ok(len) = i32::try_from(text.len()) else {
        return (0, 0);
    };
    if len == 0 {
        return (0, 0);
    }
    // SAFETY: Gets the client DC of our window; released below.
    let hdc = unsafe { windows_sys::Win32::Graphics::Gdi::GetDC(hwnd) };
    if hdc.is_null() {
        return (0, 0);
    }
    // SAFETY: Selects our live font into the DC; the previous object is restored below.
    let previous = unsafe { SelectObject(hdc, font.raw()) };
    let mut win = Rect::new(0, 0, width.max(1), 0).to_win();
    // SAFETY: `text` is live for `len` units; DT_CALCRECT only writes `win`.
    unsafe {
        DrawTextW(
            hdc,
            text.as_ptr(),
            len,
            &raw mut win,
            flags.bits() | DT_CALCRECT,
        )
    };
    if !previous.is_null() {
        // SAFETY: Restores the DC's original object.
        unsafe { SelectObject(hdc, previous) };
    }
    // SAFETY: Releases the DC obtained above.
    unsafe { windows_sys::Win32::Graphics::Gdi::ReleaseDC(hwnd, hdc) };
    (
        win.right.saturating_sub(win.left),
        win.bottom.saturating_sub(win.top),
    )
}

/// A paint session for one `WM_PAINT` (spec/01 §7.7). Created by `Window::begin_paint`.
pub struct PaintDc<'w> {
    hwnd: HWND,
    paint: PAINTSTRUCT,
    previous_font: Option<HGDIOBJ>,
    _window: PhantomData<&'w ()>,
}

impl core::fmt::Debug for PaintDc<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PaintDc")
    }
}

impl PaintDc<'_> {
    pub(crate) fn begin(hwnd: HWND) -> Result<Self, WinError> {
        let mut paint = PAINTSTRUCT {
            hdc: core::ptr::null_mut(),
            fErase: 0,
            rcPaint: RECT {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            },
            fRestore: 0,
            fIncUpdate: 0,
            rgbReserved: [0; 32],
        };
        // SAFETY: `hwnd` is the live window handling WM_PAINT; `paint` is writable storage.
        let hdc = unsafe { BeginPaint(hwnd, &raw mut paint) };
        if hdc.is_null() {
            return Err(WinError::last("BeginPaint"));
        }
        // SAFETY: `hdc` is the live paint DC returned above.
        unsafe { SetBkMode(hdc, i32::try_from(TRANSPARENT).unwrap_or(1)) };
        Ok(Self {
            hwnd,
            paint,
            previous_font: None,
            _window: PhantomData,
        })
    }

    const fn hdc(&self) -> HDC {
        self.paint.hdc
    }

    /// The invalidated area.
    #[must_use]
    pub const fn update_rect(&self) -> Rect {
        Rect::from_win(&self.paint.rcPaint)
    }

    /// Fills `rect` with `color`.
    pub fn fill_rect(&mut self, rect: Rect, color: Color) {
        // SAFETY: Creates a solid brush; it is deleted below.
        let brush = unsafe { CreateSolidBrush(color.colorref()) };
        if brush.is_null() {
            return;
        }
        let win = rect.to_win();
        // SAFETY: `hdc` is live during the paint session, `win` and `brush` are valid.
        unsafe { FillRect(self.hdc(), &raw const win, brush) };
        // SAFETY: The brush was created above and is not selected into the DC.
        unsafe { DeleteObject(brush) };
    }

    /// Draws a one-pixel border around `rect`.
    pub fn frame_rect(&mut self, rect: Rect, color: Color) {
        // SAFETY: Creates a solid brush; it is deleted below.
        let brush = unsafe { CreateSolidBrush(color.colorref()) };
        if brush.is_null() {
            return;
        }
        let win = rect.to_win();
        // SAFETY: `hdc` is live during the paint session, `win` and `brush` are valid.
        unsafe { FrameRect(self.hdc(), &raw const win, brush) };
        // SAFETY: The brush was created above and is not selected into the DC.
        unsafe { DeleteObject(brush) };
    }

    /// Fills a rounded rectangle (`radius` in pixels) outlined in `border` (pass `fill` for no
    /// visible outline).
    pub fn round_rect(&mut self, rect: Rect, radius: i32, fill: Color, border: Color) {
        if rect.w <= 0 || rect.h <= 0 {
            return;
        }
        super::controls::round_rect(self.hdc(), &rect.to_win(), radius, fill, border);
    }

    /// Fills a circle or ellipse inscribed in `rect` (a rounded rectangle with full radius).
    pub fn ellipse(&mut self, rect: Rect, fill: Color, border: Color) {
        let radius = rect.w.min(rect.h) / 2;
        self.round_rect(rect, radius, fill, border);
    }

    /// Sets the text color for subsequent draws.
    pub fn set_text_color(&mut self, color: Color) {
        // SAFETY: `hdc` is live during the paint session.
        unsafe { SetTextColor(self.hdc(), color.colorref()) };
    }

    /// Selects `font` (the original font is restored when the session ends).
    pub fn select_font(&mut self, font: &Font) {
        // SAFETY: `hdc` is live and `font` is a valid HFONT that outlives this call; the
        // original object is remembered and restored in `Drop`.
        let previous = unsafe { SelectObject(self.hdc(), font.raw()) };
        if self.previous_font.is_none() && !previous.is_null() {
            self.previous_font = Some(previous);
        }
    }

    /// Draws `text` (UTF-16, no NUL needed) inside `rect`; returns the text height.
    pub fn draw_text(&mut self, text: &[u16], rect: Rect, flags: DrawFlags) -> i32 {
        if text.is_empty() {
            return 0;
        }
        let Ok(len) = i32::try_from(text.len()) else {
            return 0;
        };
        let mut win = rect.to_win();
        // SAFETY: `text` is live for `len` units (no NUL needed with an explicit count), `win`
        // is writable, and DT_MODIFYSTRING is never set so the text is only read.
        unsafe { DrawTextW(self.hdc(), text.as_ptr(), len, &raw mut win, flags.bits()) }
    }

    /// Height `text` needs when wrapped to `width` pixels.
    pub fn measure_wrapped(&mut self, text: &[u16], width: i32, flags: DrawFlags) -> i32 {
        if text.is_empty() {
            return 0;
        }
        let Ok(len) = i32::try_from(text.len()) else {
            return 0;
        };
        let mut win = Rect::new(0, 0, width, 0).to_win();
        // SAFETY: As in `draw_text`; DT_CALCRECT only computes `win`.
        unsafe {
            DrawTextW(
                self.hdc(),
                text.as_ptr(),
                len,
                &raw mut win,
                flags.bits() | DT_CALCRECT,
            )
        };
        win.bottom.saturating_sub(win.top)
    }

    /// `(fit_chars, width)`: how many leading units fit in `max_w` pixels and the full width.
    pub fn measure(&mut self, text: &[u16], max_w: i32) -> (usize, i32) {
        let Ok(len) = i32::try_from(text.len()) else {
            return (0, 0);
        };
        let mut fit = 0_i32;
        let mut size = SIZE { cx: 0, cy: 0 };
        // SAFETY: `text` is live for `len` units; `fit` and `size` are writable; the per-char
        // extent array is not requested.
        let ok = unsafe {
            GetTextExtentExPointW(
                self.hdc(),
                text.as_ptr(),
                len,
                max_w,
                &raw mut fit,
                core::ptr::null_mut(),
                &raw mut size,
            )
        };
        if ok == 0 {
            return (0, 0);
        }
        (usize::try_from(fit).unwrap_or(0), size.cx)
    }
}

impl Drop for PaintDc<'_> {
    fn drop(&mut self) {
        if let Some(previous) = self.previous_font.take() {
            // SAFETY: Restores the DC's original font before EndPaint.
            unsafe { SelectObject(self.hdc(), previous) };
        }
        // SAFETY: Ends the paint session begun in `begin` for the same window.
        unsafe { EndPaint(self.hwnd, &raw const self.paint) };
    }
}

#[cfg(test)]
mod tests {
    use super::{Color, Rect};

    #[test]
    fn color_maps_to_bgr_colorref() {
        assert_eq!(Color(0x000F_6CBD).colorref(), 0x00BD_6C0F);
    }

    #[test]
    fn rect_helpers() {
        let rect = Rect::new(10, 20, 30, 40);
        assert!(rect.contains(10, 20));
        assert!(!rect.contains(40, 20));
        assert_eq!(rect.inset(5), Rect::new(15, 25, 20, 30));
        assert_eq!(rect.inset(100), Rect::new(110, 120, 0, 0));
        assert_eq!(Rect::from_win(&rect.to_win()), rect);
    }
}
