//! Modified UTF-7 of RFC 3501 section 5.1.3, used for mailbox names and Gmail labels.

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};

pub fn decode(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        let tail = &rest[start + 1..];
        let Some(end) = tail.find('-') else {
            out.push_str(&rest[start..]);
            return out;
        };
        if end == 0 {
            out.push('&');
        } else {
            match decode_run(&tail[..end]) {
                Some(text) => out.push_str(&text),
                None => out.push_str(&rest[start..start + end + 2]),
            }
        }
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    out
}

fn decode_run(run: &str) -> Option<String> {
    let bytes = STANDARD_NO_PAD.decode(run.replace(',', "/")).ok()?;
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

pub fn encode(s: &str) -> String {
    let mut out = String::new();
    let mut run: Vec<u16> = Vec::new();
    for c in s.chars() {
        if (' '..='~').contains(&c) {
            flush(&mut out, &mut run);
            if c == '&' {
                out.push_str("&-");
            } else {
                out.push(c);
            }
        } else {
            let mut buf = [0u16; 2];
            run.extend_from_slice(c.encode_utf16(&mut buf));
        }
    }
    flush(&mut out, &mut run);
    out
}

fn flush(out: &mut String, run: &mut Vec<u16>) {
    if run.is_empty() {
        return;
    }
    let bytes: Vec<u8> = run.iter().flat_map(|u| u.to_be_bytes()).collect();
    out.push('&');
    out.push_str(&STANDARD_NO_PAD.encode(bytes).replace('/', ","));
    out.push('-');
    run.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_names_from_several_languages() {
        for name in [
            "INBOX",
            "Gönderilmiş Öğeler",
            "Entwürfe",
            "日本語",
            "R&D",
            "a/😀",
        ] {
            assert_eq!(decode(&encode(name)), name);
        }
    }

    #[test]
    fn matches_the_rfc_examples() {
        assert_eq!(
            decode("~peter/mail/&U,BTFw-/&ZeVnLIqe-"),
            "~peter/mail/台北/日本語"
        );
        assert_eq!(
            encode("~peter/mail/台北/日本語"),
            "~peter/mail/&U,BTFw-/&ZeVnLIqe-"
        );
        assert_eq!(decode("Tom &- Jerry"), "Tom & Jerry");
    }

    #[test]
    fn leaves_broken_runs_alone() {
        assert_eq!(decode("a&b"), "a&b");
        assert_eq!(decode("a&!!-b"), "a&!!-b");
    }
}
