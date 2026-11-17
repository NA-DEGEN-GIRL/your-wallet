//! Line breaking for approval values (spec/04 §3.3): break at spaces, split a word wider than the
//! line by characters, LF is a hard break, never add characters. Joining the pieces with their
//! recorded separators gives the original text back (AP-4).

/// What separated a line from the next one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Break {
    /// One space was consumed at the break.
    Space,
    /// An LF.
    Newline,
    /// A word was split; nothing consumed.
    Split,
    /// End of text.
    End,
}

/// One laid-out line: byte range of `text` plus the separator after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line {
    /// Start byte.
    pub start: usize,
    /// End byte (exclusive).
    pub end: usize,
    /// Separator after the line.
    pub brk: Break,
}

/// Lays `text` out in lines no wider than `max_width` according to `char_width`.
#[must_use]
pub fn layout(text: &str, max_width: i32, char_width: &dyn Fn(char) -> i32) -> Vec<Line> {
    let max_width = max_width.max(1);
    let mut lines = Vec::new();
    let mut line_start = 0_usize;
    let mut line_width = 0_i32;
    let mut last_space: Option<usize> = None;
    let mut width_since_space = 0_i32;
    for (index, character) in text.char_indices() {
        if character == '\n' {
            lines.push(Line {
                start: line_start,
                end: index,
                brk: Break::Newline,
            });
            line_start = index.saturating_add(1);
            line_width = 0;
            last_space = None;
            width_since_space = 0;
            continue;
        }
        let width = char_width(character).max(0);
        if character == ' ' {
            if line_width.saturating_add(width) > max_width && index > line_start {
                lines.push(Line {
                    start: line_start,
                    end: index,
                    brk: Break::Space,
                });
                line_start = index.saturating_add(1);
                line_width = 0;
                last_space = None;
                width_since_space = 0;
                continue;
            }
            last_space = Some(index);
            line_width = line_width.saturating_add(width);
            width_since_space = 0;
            continue;
        }
        if line_width.saturating_add(width) > max_width && index > line_start {
            if let Some(space) = last_space.filter(|space| *space > line_start) {
                lines.push(Line {
                    start: line_start,
                    end: space,
                    brk: Break::Space,
                });
                line_start = space.saturating_add(1);
                line_width = width_since_space;
            }
            if line_width.saturating_add(width) > max_width && index > line_start {
                lines.push(Line {
                    start: line_start,
                    end: index,
                    brk: Break::Split,
                });
                line_start = index;
                line_width = 0;
                width_since_space = 0;
            }
            last_space = None;
        }
        line_width = line_width.saturating_add(width);
        width_since_space = width_since_space.saturating_add(width);
    }
    lines.push(Line {
        start: line_start,
        end: text.len(),
        brk: Break::End,
    });
    lines
}

/// Rebuilds the text from its lines (test oracle and copy helper).
#[must_use]
pub fn rejoin(text: &str, lines: &[Line]) -> String {
    let mut out = String::with_capacity(text.len());
    for line in lines {
        out.push_str(text.get(line.start..line.end).unwrap_or(""));
        match line.brk {
            Break::Space => out.push(' '),
            Break::Newline => out.push('\n'),
            Break::Split | Break::End => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Break, layout, rejoin};

    fn unit(_: char) -> i32 {
        1
    }

    #[test]
    fn wraps_at_spaces_and_hard_breaks() {
        let text = "aaa bbb ccc\ndd";
        let lines = layout(text, 7, &unit);
        let pieces: Vec<&str> = lines
            .iter()
            .map(|line| &text[line.start..line.end])
            .collect();
        assert_eq!(pieces, ["aaa bbb", "ccc", "dd"]);
        assert_eq!(lines[0].brk, Break::Space);
        assert_eq!(lines[1].brk, Break::Newline);
        assert_eq!(rejoin(text, &lines), text);
    }

    #[test]
    fn long_words_split_by_characters() {
        let text = "x".repeat(25);
        let lines = layout(&text, 10, &unit);
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().all(|line| line.end - line.start <= 10));
        assert_eq!(rejoin(&text, &lines), text);
    }

    #[test]
    fn multibyte_and_wide_characters_round_trip() {
        let text = "가나다 라마바사 아자차카타파하";
        let wide = |c: char| if c.is_ascii() { 1 } else { 2 };
        let lines = layout(text, 6, &wide);
        assert_eq!(rejoin(text, &lines), text);
        for line in &lines {
            let width: i32 = text[line.start..line.end].chars().map(wide).sum();
            assert!(width <= 6);
        }
    }
}
