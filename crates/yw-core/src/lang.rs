//! UI language and the fixed-text catalogues (spec/14).
//!
//! Every user-visible text exists in Korean and English side by side in one catalogue entry, so a
//! missing translation does not compile and a test can enumerate every entry. yw-core never reads a
//! global language: builders take a [`Lang`] and the approval display records it (spec/03 §11.3).

use core::fmt;

/// UI language (`settings.json` `language`, spec/04 §6.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Lang {
    /// 한국어 (default).
    #[default]
    Ko = 1,
    /// English.
    En = 2,
}

impl Lang {
    /// Both languages, Korean first.
    pub const ALL: [Self; 2] = [Self::Ko, Self::En];

    /// The display-bytes code (spec/03 §11.3): 1 Korean, 2 English.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// The `settings.json` value: `"ko"` or `"en"`.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Ko => "ko",
            Self::En => "en",
        }
    }

    /// Parses a `settings.json` value (exact, lower case).
    #[must_use]
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "ko" => Some(Self::Ko),
            "en" => Some(Self::En),
            _ => None,
        }
    }

    /// Parses a display-bytes code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Ko),
            2 => Some(Self::En),
            _ => None,
        }
    }

    /// Picks one of two values (`ko` for Korean).
    #[must_use]
    pub const fn pick<T: Copy>(self, ko: T, en: T) -> T {
        match self {
            Self::Ko => ko,
            Self::En => en,
        }
    }
}

/// A fixed text with `N` placeholders `{0}`…`{N-1}` in both languages. `Tpl<0>` is [`Text`].
///
/// The call site passes exactly `N` arguments (checked by the type); the catalogue test checks
/// that both templates use exactly the placeholders `0..N`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Tpl<const N: usize> {
    /// Korean.
    pub ko: &'static str,
    /// English.
    pub en: &'static str,
}

/// A fixed text without placeholders.
pub type Text = Tpl<0>;

impl<const N: usize> fmt::Debug for Tpl<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Tpl")
            .field("ko", &self.ko)
            .field("en", &self.en)
            .finish()
    }
}

impl<const N: usize> Tpl<N> {
    /// The template of `lang`.
    #[must_use]
    pub const fn template(self, lang: Lang) -> &'static str {
        match lang {
            Lang::Ko => self.ko,
            Lang::En => self.en,
        }
    }

    /// The text of `lang` with `{i}` replaced by `args[i]`. Any other `{` is kept as is.
    #[must_use]
    pub fn fill(self, lang: Lang, args: [&str; N]) -> String {
        let template = self.template(lang);
        let mut out = String::with_capacity(template.len());
        let mut rest = template;
        while let Some(start) = rest.find('{') {
            let (head, tail) = rest.split_at(start);
            out.push_str(head);
            if let Some(arg) = placeholder_at(tail).and_then(|index| args.get(index)) {
                out.push_str(arg);
                rest = tail.get(3..).unwrap_or("");
            } else {
                out.push('{');
                rest = tail.get(1..).unwrap_or("");
            }
        }
        out.push_str(rest);
        out
    }
}

impl Text {
    /// The text of `lang`.
    #[must_use]
    pub const fn get(self, lang: Lang) -> &'static str {
        self.template(lang)
    }
}

/// `Some(i)` when `text` starts with `{i}` (one decimal digit).
fn placeholder_at(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    match (bytes.first(), bytes.get(1), bytes.get(2)) {
        (Some(b'{'), Some(digit @ b'0'..=b'9'), Some(b'}')) => Some(usize::from(digit - b'0')),
        _ => None,
    }
}

/// The placeholder indexes used by `template`, in order of appearance (catalogue tests).
#[must_use]
pub fn placeholders(template: &str) -> Vec<usize> {
    let mut found = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let tail = rest.get(start..).unwrap_or("");
        if let Some(index) = placeholder_at(tail) {
            found.push(index);
        }
        rest = tail.get(1..).unwrap_or("");
    }
    found
}

/// One catalogue entry as data (tests, spec/14 comparison).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The constant's name.
    pub name: &'static str,
    /// Korean template.
    pub ko: &'static str,
    /// English template.
    pub en: &'static str,
    /// Number of placeholders (`N`).
    pub args: usize,
}

/// Whether `text` contains a Hangul syllable or jamo (the English catalogue must not).
#[must_use]
pub fn has_hangul(text: &str) -> bool {
    text.chars().any(|character| {
        matches!(character,
            '\u{1100}'..='\u{11FF}' | '\u{3130}'..='\u{318F}' | '\u{A960}'..='\u{A97F}'
            | '\u{AC00}'..='\u{D7AF}' | '\u{D7B0}'..='\u{D7FF}')
    })
}

/// Defines a catalogue: `NAME = "한국어" / "English";` for a [`Text`], `NAME(n) = "…{0}…" / "…";`
/// for a [`Tpl<n>`]. Also defines `pub const ALL: &[Entry]` (one catalogue per module).
#[macro_export]
macro_rules! texts {
    ($( $(#[$meta:meta])* $name:ident $(($args:literal))? = $ko:literal / $en:literal; )*) => {
        $(
            $(#[$meta])*
            #[allow(dead_code)]
            pub const $name: $crate::lang::Tpl<{ 0 $(+ $args)? }> =
                $crate::lang::Tpl { ko: $ko, en: $en };
        )*

        /// Every entry of this catalogue (tests, spec/14).
        #[allow(dead_code)]
        pub const ALL: &[$crate::lang::Entry] = &[$(
            $crate::lang::Entry { name: stringify!($name), ko: $ko, en: $en, args: 0 $(+ $args)? },
        )*];
    };
}

#[cfg(test)]
mod tests {
    use super::{Lang, Text, Tpl, has_hangul, placeholders};

    #[test]
    fn fill_replaces_only_known_placeholders() {
        let tpl: Tpl<2> = Tpl {
            ko: "{1}에게 {0} 보내기",
            en: "Send {0} to {1} {x} {9}",
        };
        assert_eq!(tpl.fill(Lang::Ko, ["1 ETH", "bob"]), "bob에게 1 ETH 보내기");
        assert_eq!(
            tpl.fill(Lang::En, ["1 ETH", "bob"]),
            "Send 1 ETH to bob {x} {9}"
        );
        assert_eq!(placeholders("{1}에게 {0} {x} {"), vec![1, 0]);
        let text: Text = Tpl { ko: "가", en: "a" };
        assert_eq!(text.get(Lang::En), "a");
        assert!(has_hangul("가") && !has_hangul("a·—→✓"));
        assert_eq!(Lang::from_tag("en"), Some(Lang::En));
        assert_eq!(Lang::from_tag("EN"), None);
        assert_eq!(Lang::from_code(Lang::Ko.code()), Some(Lang::Ko));
    }
}
