use std::collections::BTreeSet;

pub fn is_cjk_or_thai(c: char) -> bool {
    matches!(c as u32,
        0x0E00..=0x0E7F | 0x1100..=0x11FF | 0x3040..=0x30FF | 0x3400..=0x4DBF | 0x4E00..=0x9FFF
        | 0xAC00..=0xD7AF | 0xF900..=0xFAFF | 0xFF66..=0xFF9F)
}

pub fn has_cjk(texts: &[&str]) -> bool {
    texts.iter().any(|t| t.chars().any(is_cjk_or_thai))
}

/// Every pair of neighbouring CJK or Thai characters, which is how two-character words are found.
pub fn bigrams(texts: &[&str]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for t in texts {
        let mut prev: Option<char> = None;
        for c in t.chars() {
            if is_cjk_or_thai(c) {
                if let Some(p) = prev {
                    out.insert([p, c].iter().collect());
                }
                prev = Some(c);
            } else {
                prev = None;
            }
        }
    }
    out
}

/// Readable text of an HTML body, for the search index and the preview.
pub fn html_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len() / 2);
    let mut rest = html;
    while let Some(i) = rest.find(['<', '&']) {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        if rest.starts_with('<') {
            let end = rest.find('>').map_or(rest.len(), |e| e + 1);
            let closing = rest[1..].starts_with('/');
            let tag = rest[1..end].trim_start_matches('/').to_ascii_lowercase();
            rest = &rest[end..];
            for skip in ["style", "script"] {
                if !closing && tag.starts_with(skip) {
                    let lower = rest.to_ascii_lowercase();
                    let close = lower.find(&format!("</{skip}")).unwrap_or(rest.len());
                    rest = &rest[close..];
                }
            }
            out.push(' ');
        } else {
            match rest.find(';').filter(|&e| e <= 10) {
                Some(e) => match entity(&rest[1..e]) {
                    Some(c) => {
                        out.push(c);
                        rest = &rest[e + 1..];
                    }
                    None => {
                        out.push('&');
                        rest = &rest[1..];
                    }
                },
                None => {
                    out.push('&');
                    rest = &rest[1..];
                }
            }
        }
    }
    out.push_str(rest);
    out
}

fn entity(name: &str) -> Option<char> {
    match name {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        _ => {
            let num = name.strip_prefix('#')?;
            let code = match num.strip_prefix(['x', 'X']) {
                Some(h) => u32::from_str_radix(h, 16).ok()?,
                None => num.parse().ok()?,
            };
            char::from_u32(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_becomes_text() {
        let t = html_text(
            "<style>p{x:y}</style><p>Fish &amp; chips&nbsp;&#8364;5</p><br>a &lt; b &bogus; c",
        );
        assert_eq!(
            t.split_whitespace().collect::<Vec<_>>().join(" "),
            "Fish & chips €5 a < b &bogus; c"
        );
    }

    #[test]
    fn bigrams_stay_inside_runs() {
        let g = bigrams(&["会议室 a 北京"]);
        assert_eq!(g.into_iter().collect::<Vec<_>>(), ["会议", "北京", "议室"]);
    }
}
