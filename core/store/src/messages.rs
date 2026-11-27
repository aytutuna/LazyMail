use rusqlite::{params, OptionalExtension};

use crate::{Error, Result, Store};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags {
    pub seen: bool,
    pub flagged: bool,
    pub answered: bool,
    pub draft: bool,
    pub deleted: bool,
}

impl Flags {
    pub(crate) fn bits(self) -> i64 {
        (self.seen as i64)
            | (self.flagged as i64) << 1
            | (self.answered as i64) << 2
            | (self.draft as i64) << 3
            | (self.deleted as i64) << 4
    }

    pub(crate) fn from_bits(b: i64) -> Flags {
        Flags {
            seen: b & 1 != 0,
            flagged: b & 2 != 0,
            answered: b & 4 != 0,
            draft: b & 8 != 0,
            deleted: b & 16 != 0,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct NewAttachment {
    pub filename: String,
    pub mime: String,
    pub size: u32,
    pub content_id: Option<String>,
    /// MIME part path such as "2.1", or the provider's attachment id.
    pub part: String,
}

#[derive(Debug, Clone, Default)]
pub struct NewMessage {
    pub folder_id: i64,
    pub uid: Option<u32>,
    pub gm_msgid: Option<i64>,
    pub graph_id: Option<String>,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub subject: String,
    pub from_name: String,
    pub from_addr: String,
    /// Recipients as displayed, comma separated.
    pub to: String,
    pub cc: String,
    pub date: i64,
    pub size: u32,
    pub flags: Flags,
    pub labels: Vec<String>,
    pub headers: Option<String>,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub attachments: Vec<NewAttachment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub id: i64,
    pub filename: String,
    pub mime: String,
    pub size: u32,
    pub content_id: Option<String>,
    pub part: String,
    /// True while a downloaded copy is in the file store.
    pub stored: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: i64,
    pub folder_id: i64,
    pub thread_id: i64,
    pub uid: Option<u32>,
    pub gm_msgid: Option<i64>,
    pub graph_id: Option<String>,
    pub message_id: Option<String>,
    pub subject: String,
    pub from_name: String,
    pub from_addr: String,
    pub to: String,
    pub cc: String,
    pub date: i64,
    pub size: u32,
    pub flags: Flags,
    pub has_attachments: bool,
    pub headers: Option<String>,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub preview: String,
    pub labels: Vec<String>,
    pub attachments: Vec<Attachment>,
}

fn preview(body: Option<&str>) -> String {
    let body = body.unwrap_or("");
    let mut out = String::new();
    for w in body.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(w);
        if out.chars().count() >= 200 {
            break;
        }
    }
    out.chars().take(200).collect()
}

impl Store {
    pub fn insert_message(&self, m: &NewMessage) -> Result<i64> {
        self.atomic(|s| {
            let thread = s.thread_for(m)?;
            let from_text = format!("{} {}", m.from_name, m.from_addr);
            s.conn.execute(
                "INSERT INTO messages(folder_id, uid, gm_msgid, graph_id, message_id, in_reply_to,
                     thread_id, subject, from_name, from_addr, from_text, to_text, cc_text, date,
                     size, flags, has_attachments, headers, body_text, body_html, preview)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                     ?17, ?18, ?19, ?20, ?21)",
                params![
                    m.folder_id,
                    m.uid,
                    m.gm_msgid,
                    m.graph_id,
                    m.message_id,
                    m.in_reply_to,
                    thread,
                    m.subject,
                    m.from_name,
                    m.from_addr,
                    from_text,
                    m.to,
                    m.cc,
                    m.date,
                    m.size,
                    m.flags.bits(),
                    !m.attachments.is_empty(),
                    m.headers,
                    m.body_text,
                    m.body_html,
                    preview(m.body_text.as_deref()),
                ],
            )?;
            let id = s.conn.last_insert_rowid();
            let mut refs = s
                .conn
                .prepare_cached("INSERT INTO message_refs(message_id, ref) VALUES (?1, ?2)")?;
            for r in m.in_reply_to.iter().chain(&m.references) {
                refs.execute(params![id, r])?;
            }
            let mut lab = s.conn.prepare_cached(
                "INSERT OR IGNORE INTO labels(message_id, label) VALUES (?1, ?2)",
            )?;
            for l in &m.labels {
                lab.execute(params![id, l])?;
            }
            let mut att = s.conn.prepare_cached(
                "INSERT INTO attachments(message_id, filename, mime, size, content_id, part)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for a in &m.attachments {
                att.execute(params![
                    id,
                    a.filename,
                    a.mime,
                    a.size,
                    a.content_id,
                    a.part
                ])?;
            }
            Ok(id)
        })
    }

    /// Joins the threads of everything this message points to and everything pointing at it.
    fn thread_for(&self, m: &NewMessage) -> Result<i64> {
        let mut found: Vec<i64> = Vec::new();
        let mut parent = self
            .conn
            .prepare_cached("SELECT DISTINCT thread_id FROM messages WHERE message_id = ?1")?;
        for r in m.in_reply_to.iter().chain(&m.references) {
            for t in parent.query_map([r], |r| r.get(0))? {
                found.push(t?);
            }
        }
        if let Some(mid) = &m.message_id {
            let mut kids = self.conn.prepare_cached(
                "SELECT DISTINCT m.thread_id FROM message_refs r JOIN messages m ON m.id = r.message_id
                 WHERE r.ref = ?1",
            )?;
            for t in kids.query_map([mid], |r| r.get(0))? {
                found.push(t?);
            }
        }
        let Some(&keep) = found.iter().min() else {
            self.conn
                .execute("INSERT INTO threads DEFAULT VALUES", [])?;
            return Ok(self.conn.last_insert_rowid());
        };
        found.sort_unstable();
        found.dedup();
        for &t in found.iter().filter(|&&t| t != keep) {
            self.conn.execute(
                "UPDATE messages SET thread_id = ?1 WHERE thread_id = ?2",
                [keep, t],
            )?;
            self.conn
                .execute("DELETE FROM threads WHERE id = ?1", [t])?;
        }
        Ok(keep)
    }

    pub fn message(&self, id: i64) -> Result<Option<Message>> {
        let row = self
            .conn
            .query_row(
                "SELECT id, folder_id, thread_id, uid, gm_msgid, graph_id, message_id, subject,
                     from_name, from_addr, to_text, cc_text, date, size, flags, has_attachments,
                     headers, body_text, body_html, preview
                 FROM messages WHERE id = ?1",
                [id],
                |r| {
                    Ok(Message {
                        id: r.get(0)?,
                        folder_id: r.get(1)?,
                        thread_id: r.get(2)?,
                        uid: r.get(3)?,
                        gm_msgid: r.get(4)?,
                        graph_id: r.get(5)?,
                        message_id: r.get(6)?,
                        subject: r.get(7)?,
                        from_name: r.get(8)?,
                        from_addr: r.get(9)?,
                        to: r.get(10)?,
                        cc: r.get(11)?,
                        date: r.get(12)?,
                        size: r.get(13)?,
                        flags: Flags::from_bits(r.get(14)?),
                        has_attachments: r.get(15)?,
                        headers: r.get(16)?,
                        body_text: r.get(17)?,
                        body_html: r.get(18)?,
                        preview: r.get(19)?,
                        labels: Vec::new(),
                        attachments: Vec::new(),
                    })
                },
            )
            .optional()?;
        let Some(mut m) = row else { return Ok(None) };
        m.labels = self
            .conn
            .prepare("SELECT label FROM labels WHERE message_id = ?1 ORDER BY label")?
            .query_map([id], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        m.attachments = self
            .conn
            .prepare(
                "SELECT id, filename, mime, size, content_id, part, blob IS NOT NULL
                 FROM attachments WHERE message_id = ?1 ORDER BY id",
            )?
            .query_map([id], |r| {
                Ok(Attachment {
                    id: r.get(0)?,
                    filename: r.get(1)?,
                    mime: r.get(2)?,
                    size: r.get(3)?,
                    content_id: r.get(4)?,
                    part: r.get(5)?,
                    stored: r.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(Some(m))
    }

    pub fn find_by_uid(&self, folder_id: i64, uid: u32) -> Result<Option<i64>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id FROM messages WHERE folder_id = ?1 AND uid = ?2",
                params![folder_id, uid],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn find_by_graph_id(&self, graph_id: &str) -> Result<Option<i64>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id FROM messages WHERE graph_id = ?1",
                [graph_id],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Every UID in the folder with its flags, for comparing against the server.
    pub fn folder_uids(&self, folder_id: i64) -> Result<Vec<(u32, Flags)>> {
        let mut st = self.conn.prepare(
            "SELECT uid, flags FROM messages WHERE folder_id = ?1 AND uid IS NOT NULL ORDER BY uid",
        )?;
        let rows = st.query_map([folder_id], |r| {
            Ok((r.get(0)?, Flags::from_bits(r.get(1)?)))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn set_flags(&self, id: i64, flags: Flags) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE messages SET flags = ?2 WHERE id = ?1",
            params![id, flags.bits()],
        )?;
        if n == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    pub fn set_labels(&self, id: i64, labels: &[String]) -> Result<()> {
        self.atomic(|s| {
            s.conn
                .execute("DELETE FROM labels WHERE message_id = ?1", [id])?;
            let mut lab = s.conn.prepare_cached(
                "INSERT OR IGNORE INTO labels(message_id, label) VALUES (?1, ?2)",
            )?;
            for l in labels {
                lab.execute(params![id, l])?;
            }
            Ok(())
        })
    }

    pub fn set_bodies(&self, id: i64, text: Option<&str>, html: Option<&str>) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE messages SET body_text = ?2, body_html = ?3, preview = ?4 WHERE id = ?1",
            params![id, text, html, preview(text)],
        )?;
        if n == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    pub fn delete_message(&self, id: i64) -> Result<()> {
        self.atomic(|s| {
            s.evict_message_attachments(id)?;
            let thread: Option<i64> = s
                .conn
                .query_row("SELECT thread_id FROM messages WHERE id = ?1", [id], |r| r.get(0))
                .optional()?;
            s.conn.execute("DELETE FROM messages WHERE id = ?1", [id])?;
            if let Some(t) = thread {
                s.conn.execute(
                    "DELETE FROM threads WHERE id = ?1 AND NOT EXISTS (SELECT 1 FROM messages WHERE thread_id = ?1)",
                    [t],
                )?;
            }
            Ok(())
        })
    }

    /// Message ids of one thread, oldest first.
    pub fn thread_messages(&self, thread_id: i64) -> Result<Vec<i64>> {
        let mut st = self
            .conn
            .prepare("SELECT id FROM messages WHERE thread_id = ?1 ORDER BY date, id")?;
        let rows = st.query_map([thread_id], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Phone policy: drops bodies and downloaded attachments of messages older than `before`
    /// (unix seconds). Headers, previews and the subject stay, so lists and subject search still
    /// work. Returns the number of messages pruned.
    pub fn prune_bodies(&self, before: i64) -> Result<usize> {
        self.atomic(|s| {
            let ids: Vec<i64> = s
                .conn
                .prepare(
                    "SELECT id FROM messages WHERE date < ?1 AND (body_text IS NOT NULL OR body_html IS NOT NULL
                         OR EXISTS (SELECT 1 FROM attachments a WHERE a.message_id = messages.id AND a.blob IS NOT NULL))",
                )?
                .query_map([before], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            for &id in &ids {
                s.evict_message_attachments(id)?;
                s.conn
                    .execute("UPDATE messages SET body_text = NULL, body_html = NULL WHERE id = ?1", [id])?;
            }
            Ok(ids.len())
        })
    }
}
