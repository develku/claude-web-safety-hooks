//! The eight evasion-resistant normalized views.
//!
//! Ported from `generate_views()` in `scripts/web-safety-scanner.sh`, which
//! builds each view with a `perl`/`sed`/`tr` pipeline — one subprocess per view
//! per scan. Here each view is a single allocation-bounded pass.
//!
//! Fidelity over elegance: where Bash's tool is deliberately *not* Unicode-aware
//! (`tr` in the C locale) or deliberately line-scoped (`sed`), the port
//! reproduces that exactly. Quietly widening a view would make the Bash-vs-Rust
//! differential report agreement it has not earned.
//!
//! View 1 is the one rewrite the Stage-2 spike identified: its production form
//! uses look-around, which Rust's linear-time `regex` refuses to compile. Both
//! assertions are single-codepoint class tests, so it becomes a deterministic
//! forward scan — never a backtracking engine.

pub const VIEW_NAMES: [&str; 8] = [
    "lower",
    "collapsed",
    "decoded",
    "stripped",
    "confusable",
    "unicode_ws",
    "tag_stripped",
    "url_decoded",
];

pub struct Views {
    pub views: [String; 8],
}

impl Views {
    /// Bash pipes `$LOWER_OUTPUT` into `generate_views`, so every view but the
    /// baseline is derived from the already-lowercased text.
    pub fn build(content: &str) -> Views {
        let lowered = ascii_lower(content);
        Views {
            views: [
                collapsed(&lowered),
                decoded(&lowered),
                stripped(&lowered),
                confusable(&lowered),
                unicode_ws(&lowered),
                tag_stripped(&lowered),
                url_decoded(&lowered),
                lowered,
            ],
        }
        .in_declared_order()
    }

    /// The array above is built with `lowered` moved last so it can be consumed
    /// without a clone; put it back in `VIEW_NAMES` order.
    fn in_declared_order(self) -> Views {
        let [collapsed, decoded, stripped, confusable, unicode_ws, tag_stripped, url_decoded, lower] =
            self.views;
        Views {
            views: [
                lower,
                collapsed,
                decoded,
                stripped,
                confusable,
                unicode_ws,
                tag_stripped,
                url_decoded,
            ],
        }
    }
}

/// Lowercase exactly the way `tr '[:upper:]' '[:lower:]'` does in the C locale:
/// ASCII only. Rust's Unicode-aware `to_lowercase` would silently widen coverage.
pub fn ascii_lower(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        out.push(if c.is_ascii_uppercase() {
            c.to_ascii_lowercase()
        } else {
            c
        });
    }
    out
}

/// POSIX `[:space:]` in the C locale — note the vertical tab, which Rust's
/// `is_ascii_whitespace` excludes.
fn is_posix_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r')
}

fn is_lower_alpha(c: char) -> bool {
    c.is_ascii_lowercase()
}

/// View 1 — whitespace-collapsed. Catches `i g n o r e  p r e v i o u s`.
///
/// Production:
/// `s{(?<![a-z])([a-z](?: [a-z]){3,})(?![a-z])}{…}ge` then `tr -s '[:space:]' ' '`.
pub fn collapsed(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < n {
        let c = chars[i];
        // `(?<![a-z])`
        let boundary_ok = i == 0 || !is_lower_alpha(chars[i - 1]);
        if is_lower_alpha(c) && boundary_ok {
            // Greedily consume ` [a-z]` pairs.
            let mut pairs = 0usize;
            let mut j = i + 1;
            while j + 1 < n && chars[j] == ' ' && is_lower_alpha(chars[j + 1]) {
                pairs += 1;
                j += 2;
            }
            // `(?![a-z])`: the char after the run must not be a letter. Perl
            // backtracks one pair when it is; after that the run is followed by a
            // space, so a single step always suffices.
            if pairs >= 3 && j < n && is_lower_alpha(chars[j]) {
                pairs -= 1;
                j -= 2;
            }
            if pairs >= 3 {
                for k in (i..j).step_by(2) {
                    out.push(chars[k]);
                }
                i = j;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }

    squeeze_posix_space_to_space(&out)
}

/// `tr -s '[:space:]' ' '` — every whitespace run becomes one plain space.
fn squeeze_posix_space_to_space(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_ws = false;
    for c in s.chars() {
        if is_posix_space(c) {
            if !in_ws {
                out.push(' ');
                in_ws = true;
            }
        } else {
            in_ws = false;
            out.push(c);
        }
    }
    out
}

/// View 2 — HTML entities decoded (numeric decimal + hex, then the four named
/// entities production's `sed` handles), NULs dropped.
pub fn decoded(input: &str) -> String {
    const NAMED: [(&str, char); 4] = [
        ("&lt;", '<'),
        ("&gt;", '>'),
        ("&amp;", '&'),
        ("&quot;", '"'),
    ];

    let b = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'&' && i + 2 < b.len() && b[i + 1] == b'#' {
            let hex = b[i + 2] == b'x' || b[i + 2] == b'X';
            let start = if hex { i + 3 } else { i + 2 };
            let mut j = start;
            while j < b.len()
                && ((hex && b[j].is_ascii_hexdigit()) || (!hex && b[j].is_ascii_digit()))
            {
                j += 1;
            }
            if j > start && j < b.len() && b[j] == b';' {
                let digits = &input[start..j];
                let code = if hex {
                    u32::from_str_radix(digits, 16).ok()
                } else {
                    digits.parse::<u32>().ok()
                };
                // perl's guard is `<= 0x10FFFF`; anything it cannot encode is
                // left as the literal entity text.
                if let Some(c) = code.filter(|c| *c <= 0x10FFFF).and_then(char::from_u32) {
                    // `tr -d '\000'` runs last in the pipeline, so a `&#0;` that
                    // decodes to NUL is dropped here too.
                    if c != '\0' {
                        out.push(c);
                    }
                    i = j + 1;
                    continue;
                }
            }
        }

        if let Some((name, repl)) = NAMED.iter().find(|(n, _)| input[i..].starts_with(n)) {
            out.push(*repl);
            i += name.len();
            continue;
        }

        let c = input[i..].chars().next().expect("i is a char boundary");
        // A literal NUL would make grep treat the whole view as binary and skip it.
        if c != '\0' {
            out.push(c);
        }
        i += c.len_utf8();
    }
    out
}

/// View 3 — punctuation/separator stripped, then whitespace runs squashed.
/// Production char class: `[._*|,;:!?+=#~\/-]`.
pub fn stripped(input: &str) -> String {
    const STRIP: &[char] = &[
        '.', '_', '*', '|', ',', ';', ':', '!', '?', '+', '=', '#', '~', '\\', '/', '-',
    ];
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if !STRIP.contains(&c) {
            out.push(c);
        }
    }
    // `sed 's/[[:space:]]\{1,\}/ /g'`
    squeeze_posix_space_to_space(&out)
}

/// View 4 — Unicode confusable folding plus combining-mark / variation-selector
/// removal. The map is the production `sed` chain, entry for entry.
pub fn confusable(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        // Laid out to stay diffable against the production sed chain.
        #[rustfmt::skip]
        let mapped = match c {
            'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c', 'у' => 'y',
            'х' => 'x', 'і' => 'i', 'ј' => 'j', 'ѕ' => 's', 'ԁ' => 'd', 'ɡ' => 'g',
            'ɑ' => 'a', 'ε' => 'e', 'ο' => 'o', 'ν' => 'v', 'ι' => 'i', 'κ' => 'k',
            'τ' => 't', 'η' => 'n',
            // Fullwidth Latin small letters ａ..ｚ (U+FF41..U+FF5A).
            'ａ'..='ｚ' => char::from_u32(c as u32 - 0xFF41 + 'a' as u32).unwrap_or(c),
            other => other,
        };
        // `s/[\x{0300}-\x{036F}\x{FE00}-\x{FE0F}]//g`
        let cp = mapped as u32;
        if (0x0300..=0x036F).contains(&cp) || (0xFE00..=0xFE0F).contains(&cp) {
            continue;
        }
        out.push(mapped);
    }
    out
}

/// View 5 — Unicode whitespace normalized, then `tr -s ' '`. Only literal spaces
/// are squeezed here; tabs and newlines survive, unlike view 1.
pub fn unicode_ws(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_space = false;
    for c in input.chars() {
        let mapped = match c {
            '\u{00A0}' | '\u{2002}' | '\u{2003}' | '\u{200A}' | '\u{3000}' => ' ',
            other => other,
        };
        if mapped == ' ' {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
        } else {
            prev_space = false;
            out.push(mapped);
        }
    }
    out
}

/// View 6 — HTML/XML tags removed. `sed 's/<[^>]*>//g'` is line-oriented, so an
/// unterminated `<` never swallows the rest of the document.
pub fn tag_stripped(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for (idx, line) in input.split('\n').enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        let mut rest = line;
        loop {
            let Some(lt) = rest.find('<') else {
                out.push_str(rest);
                break;
            };
            match rest[lt..].find('>') {
                Some(rel_gt) => {
                    out.push_str(&rest[..lt]);
                    rest = &rest[lt + rel_gt + 1..];
                }
                None => {
                    out.push_str(rest);
                    break;
                }
            }
        }
    }
    out
}

/// View 7 — URL percent-decoding. perl decodes to raw bytes, so invalid UTF-8 is
/// possible; production greps that byte stream directly. Decoding on bytes and
/// converting lossily keeps every ASCII match intact.
pub fn url_decoded(input: &str) -> String {
    let b = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && b[i + 1].is_ascii_hexdigit()
            && b[i + 2].is_ascii_hexdigit()
        {
            let hi = (b[i + 1] as char).to_digit(16).expect("hex digit") as u8;
            let lo = (b[i + 2] as char).to_digit(16).expect("hex digit") as u8;
            out.push(hi * 16 + lo);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- view 0: lower -------------------------------------------------------

    #[test]
    fn view0_lower_is_ascii_only_like_tr_in_the_c_locale() {
        // `tr '[:upper:]' '[:lower:]'` does NOT fold non-ASCII. Folding it here
        // would widen Rust's coverage past Bash and make the differential lie.
        assert_eq!(ascii_lower("IGNORE Ä İ"), "ignore Ä İ");
    }

    // --- view 1: collapsed ---------------------------------------------------

    #[test]
    fn view1_collapsed_reassembles_spaced_single_letters() {
        let got = collapsed("i g n o r e  p r e v i o u s instructions");
        assert!(got.contains("ignore"), "{got:?}");
        assert!(got.contains("previous"), "{got:?}");
    }

    #[test]
    fn view1_collapsed_needs_four_letters_and_respects_word_boundaries() {
        assert_eq!(collapsed("a b c d"), "abcd");
        assert_eq!(collapsed("a b c"), "a b c");
    }

    #[test]
    fn view1_collapsed_backtracks_one_pair_before_a_letter_run() {
        // The production perl regex ends with `(?![a-z])`; the greedy run here
        // stops immediately before `ef`, so perl gives back one pair.
        assert_eq!(collapsed("a b c d ef"), "abcd ef");
    }

    #[test]
    fn view1_collapsed_squeezes_whitespace_runs_to_one_space() {
        assert_eq!(collapsed("a\t\t b\n\nc"), "a b c");
    }

    // --- view 2: decoded -----------------------------------------------------

    #[test]
    fn view2_decoded_handles_decimal_and_hex_entities() {
        assert!(decoded("&#x69;gnore &#112;revious").contains("ignore previous"));
        assert!(decoded("&#105;gnore").contains("ignore"));
    }

    #[test]
    fn view2_decoded_handles_the_four_named_entities_bash_sed_handles() {
        assert_eq!(decoded("&lt;a&gt;&amp;&quot;"), "<a>&\"");
    }

    #[test]
    fn view2_decoded_drops_nuls_so_grep_never_sees_the_view_as_binary() {
        assert_eq!(decoded("ig\0nore"), "ignore");
        assert_eq!(decoded("ig&#0;nore"), "ignore");
    }

    #[test]
    fn view2_decoded_leaves_out_of_range_entities_literal() {
        // perl's guard is `<= 0x10FFFF`.
        assert_eq!(decoded("&#x110000;"), "&#x110000;");
    }

    // --- view 3: stripped ----------------------------------------------------

    #[test]
    fn view3_stripped_removes_separator_punctuation() {
        assert!(stripped("i.g.n.o.r.e p-r-e-v-i-o-u-s").contains("ignore previous"));
        assert!(stripped("i_g_n_o_r_e").contains("ignore"));
    }

    // --- view 4: confusable --------------------------------------------------

    #[test]
    fn view4_confusable_folds_cyrillic_greek_and_fullwidth() {
        assert!(confusable("іgnоre").contains("ignore"));
        assert!(confusable("ｉｇｎｏｒｅ").contains("ignore"));
        assert!(confusable("ιgnοre").contains("ignore"));
    }

    #[test]
    fn view4_confusable_drops_combining_marks_and_variation_selectors() {
        assert_eq!(confusable("i\u{0301}g\u{FE0F}n"), "ign");
    }

    // --- view 5: unicode_ws --------------------------------------------------

    #[test]
    fn view5_unicode_ws_maps_exotic_spaces_then_squeezes_plain_spaces_only() {
        assert_eq!(unicode_ws("a\u{00A0}\u{3000}b"), "a b");
        // `tr -s ' '` squeezes spaces, NOT tabs/newlines — unlike view 1.
        assert_eq!(unicode_ws("a\t\tb"), "a\t\tb");
    }

    // --- view 6: tag_stripped ------------------------------------------------

    #[test]
    fn view6_tag_stripped_removes_inline_tags() {
        assert_eq!(tag_stripped("ign<span></span>ore"), "ignore");
    }

    #[test]
    fn view6_tag_stripped_is_line_scoped_so_a_lone_lt_cannot_eat_the_document() {
        // `sed 's/<[^>]*>//g'` never matches across a newline.
        assert_eq!(tag_stripped("a < b\nc > d"), "a < b\nc > d");
    }

    // --- view 7: url_decoded -------------------------------------------------

    #[test]
    fn view7_url_decoded_decodes_percent_escapes() {
        assert!(url_decoded("%69gnore %70revious").contains("ignore previous"));
    }

    #[test]
    fn view7_url_decoded_leaves_a_malformed_escape_alone() {
        assert_eq!(url_decoded("100%; %zz"), "100%; %zz");
    }

    // --- the set -------------------------------------------------------------

    #[test]
    fn build_produces_all_eight_named_views() {
        let v = Views::build("Hello");
        assert_eq!(VIEW_NAMES.len(), 8);
        assert_eq!(v.views.len(), 8);
        assert_eq!(
            VIEW_NAMES,
            [
                "lower",
                "collapsed",
                "decoded",
                "stripped",
                "confusable",
                "unicode_ws",
                "tag_stripped",
                "url_decoded"
            ]
        );
    }
}
