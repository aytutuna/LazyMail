//! Reads FETCH replies into owned values and turns headers and MIME parts into store rows.

use std::borrow::Cow;

use async_imap::imap_proto::{
    AttributeValue, BodyContentCommon, BodyStructure, MessageSection, SectionPath,
};
use lazymail_store::{Flags, NewAttachment, NewMessage};
use mail_parser::MessageParser;

use crate::utf7;

/// Where the text of a message sits and what else it carries, from BODYSTRUCTURE.
#[derive(Debug, Default, Clone)]
pub(crate) struct Layout {
    pub plain: Vec<String>,
    pub html: Vec<String>,
    pub attachments: Vec<NewAttachment>,
}

#[derive(Debug, Default)]
pub(crate) struct Fetched {
    pub uid: u32,
    pub flags: Option<Flags>,
    pub modseq: Option<u64>,
    pub size: Option<u32>,
    pub date: Option<i64>,
    pub header: Option<Vec<u8>>,
    pub layout: Option<Layout>,
    pub gm_msgid: Option<i64>,
    pub labels: Option<Vec<String>>,
    /// BODY[part] and BODY[part.MIME] contents: the part path, whether it is the MIME header,
    /// and the bytes.
    pub sections: Vec<(Vec<u32>, bool, Vec<u8>)>,
}

impl Fetched {
    /// Adds what another response for the same message carried; a server may split one
    /// message's data over several FETCH responses.
    pub(crate) fn merge(&mut self, o: Fetched) {
        macro_rules! take {
            ($($f:ident),*) => { $(if o.$f.is_some() { self.$f = o.$f; })* };
        }
        take!(flags, modseq, size, date, header, layout, gm_msgid, labels);
        self.sections.extend(o.sections);
    }

    /// The header block and the raw body of a part. A message that is not multipart has no
    /// MIME header of its own for part 1 on some servers; its message header stands in.
    pub(crate) fn part(&self, path: &[u32]) -> Option<(&[u8], &[u8])> {
        let find = |mime| {
            self.sections
                .iter()
                .find(|(p, m, _)| p == path && *m == mime)
                .map(|(_, _, d)| d.as_slice())
        };
        let body = find(false)?;
        let mime = find(true).filter(|m| !m.is_empty()).or(if path == [1] {
            self.header.as_deref()
        } else {
            None
        })?;
        Some((mime, body))
    }
}

/// The FETCH items that bring the given parts.
pub(crate) fn part_items<'a>(parts: impl IntoIterator<Item = &'a String>) -> String {
    let mut items = Vec::new();
    for p in parts {
        items.push(format!("BODY.PEEK[{p}.MIME] BODY.PEEK[{p}]"));
        if p == "1" {
            items.push("BODY.PEEK[HEADER]".to_string());
        }
    }
    items.join(" ")
}

pub(crate) fn flags_of<'a>(names: impl IntoIterator<Item = &'a str>) -> Flags {
    let mut f = Flags::default();
    for n in names {
        match n.to_ascii_lowercase().as_str() {
            "\\seen" => f.seen = true,
            "\\flagged" => f.flagged = true,
            "\\answered" => f.answered = true,
            "\\draft" => f.draft = true,
            "\\deleted" => f.deleted = true,
            _ => {}
        }
    }
    f
}

pub(crate) fn fetched(attrs: &[AttributeValue<'_>]) -> Option<Fetched> {
    let mut f = Fetched::default();
    for a in attrs {
        match a {
            AttributeValue::Uid(u) => f.uid = *u,
            AttributeValue::Flags(v) => f.flags = Some(flags_of(v.iter().map(|c| c.as_ref()))),
            AttributeValue::ModSeq(m) => f.modseq = Some(*m),
            AttributeValue::Rfc822Size(s) => f.size = Some(*s),
            AttributeValue::InternalDate(d) => f.date = internal_date(d),
            AttributeValue::GmailMsgId(id) => f.gm_msgid = Some(*id as i64),
            AttributeValue::GmailLabels(v) => {
                f.labels = Some(v.iter().map(|l| utf7::decode(&unescape(l))).collect())
            }
            AttributeValue::BodyStructure(b) => f.layout = Some(layout(b)),
            AttributeValue::BodySection {
                section,
                data: Some(data),
                ..
            } => match section {
                Some(SectionPath::Full(MessageSection::Header)) => f.header = Some(data.to_vec()),
                Some(SectionPath::Part(path, None)) => {
                    f.sections.push((path.clone(), false, data.to_vec()))
                }
                Some(SectionPath::Part(path, Some(MessageSection::Mime))) => {
                    f.sections.push((path.clone(), true, data.to_vec()))
                }
                _ => {}
            },
            _ => {}
        }
    }
    (f.uid != 0).then_some(f)
}

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

/// "17-Jul-1996 02:44:25 -0700" as unix seconds.
fn internal_date(s: &str) -> Option<i64> {
    let (date, rest) = s.trim().split_once(' ')?;
    let (time, zone) = rest.split_once(' ')?;
    let mut d = date.split('-');
    let day: i64 = d.next()?.trim().parse().ok()?;
    let name = d.next()?;
    let month = MONTHS.iter().position(|m| name.eq_ignore_ascii_case(m))? as i64 + 1;
    let year: i64 = d.next()?.parse().ok()?;
    let mut t = time.split(':');
    let h: i64 = t.next()?.parse().ok()?;
    let m: i64 = t.next()?.parse().ok()?;
    let sec: i64 = t.next()?.parse().ok()?;
    let sign = if zone.starts_with('-') { -1 } else { 1 };
    let z: i64 = zone.get(1..5)?.parse().ok()?;
    let offset = sign * ((z / 100) * 3600 + (z % 100) * 60);
    Some(days_from_civil(year, month, day) * 86400 + h * 3600 + m * 60 + sec - offset)
}

// Days since 1970-01-01 of a calendar date (Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn layout(b: &BodyStructure<'_>) -> Layout {
    let mut l = Layout::default();
    walk(b, Vec::new(), &mut l);
    l
}

fn walk(b: &BodyStructure<'_>, path: Vec<u32>, l: &mut Layout) {
    match b {
        BodyStructure::Multipart { bodies, .. } => {
            for (i, child) in bodies.iter().enumerate() {
                let mut p = path.clone();
                p.push(i as u32 + 1);
                walk(child, p, l);
            }
        }
        BodyStructure::Text { common, other, .. } => {
            let part = part_name(&path);
            let attached = common
                .disposition
                .as_ref()
                .is_some_and(|d| d.ty.eq_ignore_ascii_case("attachment"));
            let sub = common.ty.subtype.to_ascii_lowercase();
            if !attached && filename(common).is_none() && (sub == "plain" || sub == "html") {
                if sub == "plain" {
                    l.plain.push(part);
                } else {
                    l.html.push(part);
                }
            } else {
                l.attachments
                    .push(attachment(common, &other.id, other.octets, part));
            }
        }
        BodyStructure::Basic { common, other, .. }
        | BodyStructure::Message { common, other, .. } => {
            l.attachments.push(attachment(
                common,
                &other.id,
                other.octets,
                part_name(&path),
            ));
        }
    }
}

fn part_name(path: &[u32]) -> String {
    if path.is_empty() {
        return "1".into();
    }
    path.iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

pub(crate) fn part_path(part: &str) -> Vec<u32> {
    part.split('.').filter_map(|p| p.parse().ok()).collect()
}

fn attachment(
    common: &BodyContentCommon<'_>,
    id: &Option<Cow<'_, str>>,
    octets: u32,
    part: String,
) -> NewAttachment {
    NewAttachment {
        filename: filename(common).unwrap_or_default(),
        mime: format!(
            "{}/{}",
            common.ty.ty.to_ascii_lowercase(),
            common.ty.subtype.to_ascii_lowercase()
        ),
        size: octets,
        content_id: id
            .as_ref()
            .map(|c| c.trim().trim_matches(['<', '>']).to_string())
            .filter(|c| !c.is_empty()),
        inline: common
            .disposition
            .as_ref()
            .is_some_and(|d| d.ty.eq_ignore_ascii_case("inline")),
        part,
    }
}

fn filename(common: &BodyContentCommon<'_>) -> Option<String> {
    common
        .disposition
        .as_ref()
        .and_then(|d| param(&d.params, "filename"))
        .or_else(|| param(&common.ty.params, "name"))
}

type Params<'a> = Option<Vec<(Cow<'a, str>, Cow<'a, str>)>>;

/// A parameter by name, read plain, as an encoded word, or as an RFC 2231 value in one or
/// several pieces.
fn param(params: &Params<'_>, name: &str) -> Option<String> {
    let params = params.as_ref()?;
    let find = |key: &str| {
        params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| unescape(v))
    };
    if let Some(v) = find(name) {
        return Some(decode_words(&v));
    }
    if let Some(v) = find(&format!("{name}*")) {
        return Some(decode_2231(&v));
    }
    let prefix = format!("{name}*");
    let mut pieces: Vec<(u32, bool, &str)> = Vec::new();
    for (k, v) in params {
        let k = k.to_ascii_lowercase();
        let Some(rest) = k.strip_prefix(&prefix) else {
            continue;
        };
        let (n, encoded) = match rest.strip_suffix('*') {
            Some(n) => (n, true),
            None => (rest, false),
        };
        if let Ok(n) = n.parse() {
            pieces.push((n, encoded, v));
        }
    }
    if pieces.is_empty() {
        return None;
    }
    pieces.sort_by_key(|p| p.0);
    let mut out = String::new();
    for (i, (_, encoded, v)) in pieces.iter().enumerate() {
        match (*encoded, i) {
            (true, 0) => out.push_str(&decode_2231(v)),
            (true, _) => out.push_str(&percent(v)),
            (false, _) => out.push_str(v),
        }
    }
    Some(out)
}

fn decode_words(s: &str) -> String {
    if !s.contains("=?") {
        return s.to_string();
    }
    let raw = format!("Subject: {s}\r\n\r\n");
    MessageParser::default()
        .parse(raw.as_bytes())
        .and_then(|m| m.subject().map(str::to_string))
        .unwrap_or_else(|| s.to_string())
}

// charset'language'percent-encoded text; the charset is taken to be UTF-8.
fn decode_2231(v: &str) -> String {
    match v.splitn(3, '\'').collect::<Vec<_>>().as_slice() {
        [_, _, text] => percent(text),
        _ => percent(v),
    }
}

fn percent(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if let Some(x) = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(x);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn display(name: Option<&str>, address: Option<&str>) -> String {
    match (name, address) {
        (Some(n), Some(a)) if !n.is_empty() => format!("{n} <{a}>"),
        (_, Some(a)) => a.to_string(),
        (Some(n), None) => n.to_string(),
        _ => String::new(),
    }
}

/// The header row of a message: addresses, subject, ids and the references for threading.
pub(crate) fn new_message(folder_id: i64, f: &Fetched) -> NewMessage {
    let header = f.header.as_deref().unwrap_or_default();
    let mut m = NewMessage {
        folder_id,
        uid: Some(f.uid),
        gm_msgid: f.gm_msgid,
        size: f.size.unwrap_or(0),
        flags: f.flags.unwrap_or_default(),
        labels: f.labels.clone().unwrap_or_default(),
        headers: f
            .header
            .as_ref()
            .map(|h| String::from_utf8_lossy(h).into_owned()),
        attachments: f
            .layout
            .as_ref()
            .map(|l| l.attachments.clone())
            .unwrap_or_default(),
        date: f.date.unwrap_or(0),
        ..Default::default()
    };
    let Some(p) = MessageParser::default().parse(header) else {
        return m;
    };
    m.subject = p.subject().unwrap_or("").to_string();
    if let Some(from) = p.from().and_then(|a| a.first()) {
        m.from_name = from.name().unwrap_or("").to_string();
        m.from_addr = from.address().unwrap_or("").to_string();
    }
    let list = |a: Option<mail_parser::AddressList<'_>>| {
        a.map(|a| {
            a.mailboxes()
                .map(|b| display(b.name(), b.address()))
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
    };
    m.to = list(p.to());
    m.cc = list(p.cc());
    if let Some(d) = p.date() {
        m.date = d.to_timestamp();
    }
    m.message_id = p.message_id().map(str::to_string);
    m.in_reply_to = p.in_reply_to().and_then(|l| l.first()).map(str::to_string);
    m.references = p
        .references()
        .map(|l| l.iter().map(str::to_string).collect())
        .unwrap_or_default();
    m
}

// The part's own header block followed by its body parses as a one-part message.
fn part_message(mime: &[u8], body: &[u8]) -> Vec<u8> {
    let mut raw = mime.to_vec();
    while matches!(raw.last(), Some(b'\r' | b'\n')) {
        raw.pop();
    }
    raw.extend_from_slice(b"\r\n\r\n");
    raw.extend_from_slice(body);
    raw
}

pub(crate) fn decode_text(mime: &[u8], body: &[u8]) -> String {
    let raw = part_message(mime, body);
    MessageParser::default()
        .parse(&raw)
        .and_then(|m| m.root_part().text().map(|t| t.into_owned()))
        .unwrap_or_default()
}

pub(crate) fn decode_bytes(mime: &[u8], body: &[u8]) -> Vec<u8> {
    let raw = part_message(mime, body);
    MessageParser::default()
        .parse(&raw)
        .map(|m| m.root_part().decoded().into_owned())
        .unwrap_or_default()
}

/// The parser hands quoted strings over with their backslash escapes still in.
pub(crate) fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match (c, chars.clone().next()) {
            ('\\', Some(n @ ('\\' | '"'))) => {
                out.push(n);
                chars.next();
            }
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_dates_carry_their_zone() {
        assert_eq!(internal_date("01-Jan-1970 00:00:00 +0000"), Some(0));
        assert_eq!(
            internal_date("17-Jul-1996 02:44:25 -0700"),
            Some(837_596_665)
        );
        assert_eq!(
            internal_date(" 3-Jan-2023 10:00:00 +0130"),
            Some(1_672_734_600)
        );
        assert_eq!(internal_date("nonsense"), None);
    }

    fn params(list: &[(&'static str, &'static str)]) -> Params<'static> {
        Some(
            list.iter()
                .map(|(k, v)| (Cow::Borrowed(*k), Cow::Borrowed(*v)))
                .collect(),
        )
    }

    #[test]
    fn file_names_come_out_of_all_three_encodings() {
        assert_eq!(
            param(&params(&[("NAME", "plain.txt")]), "name").unwrap(),
            "plain.txt"
        );
        assert_eq!(
            param(
                &params(&[("name", "=?utf-8?Q?r=C3=A9sum=C3=A9.pdf?=")]),
                "name"
            )
            .unwrap(),
            "résumé.pdf"
        );
        assert_eq!(
            param(
                &params(&[("filename*", "utf-8''%e2%82%ac%20rates.txt")]),
                "filename"
            )
            .unwrap(),
            "€ rates.txt"
        );
        assert_eq!(
            param(
                &params(&[
                    ("filename*1", "tables.gif"),
                    ("filename*0*", "utf-8''Book%20about%20"),
                ]),
                "filename"
            )
            .unwrap(),
            "Book about tables.gif"
        );
        assert_eq!(param(&None, "name"), None);
    }

    #[test]
    fn quoted_escapes_are_removed() {
        assert_eq!(unescape(r#"\\Inbox"#), r"\Inbox");
        assert_eq!(unescape(r#"say \"hi\""#), r#"say "hi""#);
        assert_eq!(unescape("plain"), "plain");
    }

    #[test]
    fn a_part_with_its_own_header_decodes() {
        let mime = b"Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n";
        assert_eq!(decode_text(mime, b"Caf=E9"), "Café");
        let bin = b"Content-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\n\r\n";
        assert_eq!(decode_bytes(bin, b"AAEC/w=="), [0, 1, 2, 255]);
    }
}
