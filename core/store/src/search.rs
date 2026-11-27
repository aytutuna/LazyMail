use rusqlite::types::Value;
use rusqlite::{params, params_from_iter};

use crate::messages::Flags;
use crate::{Result, Store};

/// Snippets mark matches between these two control characters.
pub const MARK_START: char = '\u{1}';
pub const MARK_END: char = '\u{2}';

#[derive(Debug, Clone, Default)]
pub struct SearchQuery {
    pub text: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub subject: Option<String>,
    pub folder_id: Option<i64>,
    /// Inclusive, unix seconds.
    pub after: Option<i64>,
    /// Exclusive, unix seconds.
    pub before: Option<i64>,
    pub has_attachment: bool,
    pub unread: bool,
    pub flagged: bool,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    pub message_id: i64,
    pub folder_id: i64,
    pub thread_id: i64,
    pub subject: String,
    pub from_name: String,
    pub from_addr: String,
    pub date: i64,
    pub flags: Flags,
    pub has_attachments: bool,
    /// The match in context with MARK_START and MARK_END around it, or the preview when the
    /// query had no text or was too short for the index.
    pub snippet: String,
}

fn is_cjk_or_thai(c: char) -> bool {
    matches!(c as u32,
        0x0E00..=0x0E7F | 0x1100..=0x11FF | 0x3040..=0x30FF | 0x3400..=0x4DBF | 0x4E00..=0x9FFF
        | 0xAC00..=0xD7AF | 0xF900..=0xFAFF | 0xFF66..=0xFF9F)
}

fn like(s: &str) -> String {
    let mut out = String::from("%");
    for c in s.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

/// Matches above this count take the date-index route.
const COMMON: usize = 2000;

enum Text {
    None,
    Words(String),
    Trigrams(String),
    Substrings(Vec<String>),
}

fn plan(text: &str) -> Text {
    let words: Vec<String> = text
        .split_whitespace()
        .map(|w| w.replace('"', ""))
        .filter(|w| !w.is_empty())
        .collect();
    if words.is_empty() {
        return Text::None;
    }
    if text.chars().any(is_cjk_or_thai) {
        if words.iter().all(|w| w.chars().count() >= 3) {
            return Text::Trigrams(
                words
                    .iter()
                    .map(|w| format!("\"{w}\""))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }
        return Text::Substrings(words);
    }
    let last = words.len() - 1;
    let terms: Vec<String> = words
        .iter()
        .enumerate()
        .map(|(i, w)| {
            if i == last {
                format!("\"{w}\"*")
            } else {
                format!("\"{w}\"")
            }
        })
        .collect();
    Text::Words(terms.join(" "))
}

impl Store {
    /// Keyword search, newest first.
    pub fn search(&self, q: &SearchQuery) -> Result<Vec<SearchHit>> {
        let mut sql = String::from("SELECT m.id FROM messages m");
        let mut args: Vec<Value> = Vec::new();
        let mut conds: Vec<String> = Vec::new();
        let (table, matcher) = match plan(&q.text) {
            Text::None => (None, None),
            Text::Words(m) => (Some("msg_fts"), Some(m)),
            Text::Trigrams(m) => (Some("msg_tri"), Some(m)),
            Text::Substrings(words) => {
                for w in words {
                    conds.push(
                        "(m.subject LIKE ? ESCAPE '\\' OR m.from_text LIKE ? ESCAPE '\\' OR m.body_text LIKE ? ESCAPE '\\')"
                            .into(),
                    );
                    for _ in 0..3 {
                        args.push(Value::Text(like(&w)));
                    }
                }
                (None, None)
            }
        };
        if let (Some(t), Some(m)) = (table, &matcher) {
            // A rare match is sorted by date after the lookup. A common one would sort tens of
            // thousands of rows, so the date index is walked newest first instead and the
            // index only answers membership.
            let ids: Vec<i64> = self
                .conn
                .prepare_cached(&format!(
                    "SELECT rowid FROM {t} WHERE {t} MATCH ?1 LIMIT ?2"
                ))?
                .query_map(params![m, COMMON as i64 + 1], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            if ids.len() <= COMMON {
                let marks = vec!["?"; ids.len()].join(",");
                conds.push(format!("m.id IN ({marks})"));
                args.extend(ids.into_iter().map(Value::Integer));
            } else {
                conds.push(format!(
                    "+m.id IN (SELECT rowid FROM {t} WHERE {t} MATCH ?)"
                ));
                args.push(Value::Text(m.clone()));
            }
        }
        for (col, v) in [
            ("m.from_text", &q.from),
            ("m.to_text", &q.to),
            ("m.subject", &q.subject),
        ] {
            if let Some(v) = v {
                conds.push(format!("{col} LIKE ? ESCAPE '\\'"));
                args.push(Value::Text(like(v)));
            }
        }
        if let Some(f) = q.folder_id {
            conds.push("m.folder_id = ?".into());
            args.push(Value::Integer(f));
        }
        if let Some(d) = q.after {
            conds.push("m.date >= ?".into());
            args.push(Value::Integer(d));
        }
        if let Some(d) = q.before {
            conds.push("m.date < ?".into());
            args.push(Value::Integer(d));
        }
        if q.has_attachment {
            conds.push("m.has_attachments = 1".into());
        }
        if q.unread {
            conds.push("m.flags & 1 = 0".into());
        }
        if q.flagged {
            conds.push("m.flags & 2 != 0".into());
        }
        if !conds.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conds.join(" AND "));
        }
        sql.push_str(" ORDER BY m.date DESC, m.id DESC LIMIT ? OFFSET ?");
        args.push(Value::Integer(
            if q.limit == 0 { 50 } else { q.limit } as i64
        ));
        args.push(Value::Integer(q.offset as i64));

        let ids: Vec<i64> = self
            .conn
            .prepare(&sql)?
            .query_map(params_from_iter(args), |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;

        let mut hits = Vec::with_capacity(ids.len());
        let mut head = self.conn.prepare_cached(
            "SELECT folder_id, thread_id, subject, from_name, from_addr, date, flags, has_attachments, preview
             FROM messages WHERE id = ?1",
        )?;
        for id in ids {
            let mut hit = head.query_row([id], |r| {
                Ok(SearchHit {
                    message_id: id,
                    folder_id: r.get(0)?,
                    thread_id: r.get(1)?,
                    subject: r.get(2)?,
                    from_name: r.get(3)?,
                    from_addr: r.get(4)?,
                    date: r.get(5)?,
                    flags: Flags::from_bits(r.get(6)?),
                    has_attachments: r.get(7)?,
                    snippet: r.get(8)?,
                })
            })?;
            if let (Some(t), Some(m)) = (table, &matcher) {
                let mut sn = self.conn.prepare_cached(&format!(
                    "SELECT snippet({t}, -1, char(1), char(2), '…', 16) FROM {t} WHERE {t} MATCH ?1 AND rowid = ?2"
                ))?;
                if let Ok(s) = sn.query_row(params![m, id], |r| r.get::<_, String>(0)) {
                    hit.snippet = s;
                }
            }
            hits.push(hit);
        }
        Ok(hits)
    }
}
