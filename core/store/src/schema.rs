use rusqlite::Connection;

use crate::{Error, Result};

const MIGRATIONS: &[&str] = &[V1];

pub fn migrate(conn: &Connection) -> Result<()> {
    let current: u32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if current as usize > MIGRATIONS.len() {
        return Err(Error::TooNew(current));
    }
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(current as usize) {
        conn.execute_batch(&format!(
            "BEGIN; {sql} PRAGMA user_version = {}; COMMIT;",
            i + 1
        ))?;
    }
    Ok(())
}

const V1: &str = "
CREATE TABLE folders(
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    role TEXT,
    uidvalidity INTEGER,
    uidnext INTEGER,
    highestmodseq INTEGER,
    delta_link TEXT
);

CREATE TABLE threads(id INTEGER PRIMARY KEY);

CREATE TABLE messages(
    id INTEGER PRIMARY KEY,
    folder_id INTEGER NOT NULL REFERENCES folders(id),
    uid INTEGER,
    gm_msgid INTEGER,
    graph_id TEXT,
    message_id TEXT,
    in_reply_to TEXT,
    thread_id INTEGER NOT NULL REFERENCES threads(id),
    subject TEXT NOT NULL DEFAULT '',
    from_name TEXT NOT NULL DEFAULT '',
    from_addr TEXT NOT NULL DEFAULT '',
    from_text TEXT NOT NULL DEFAULT '',
    to_text TEXT NOT NULL DEFAULT '',
    cc_text TEXT NOT NULL DEFAULT '',
    date INTEGER NOT NULL,
    size INTEGER NOT NULL DEFAULT 0,
    flags INTEGER NOT NULL DEFAULT 0,
    has_attachments INTEGER NOT NULL DEFAULT 0,
    headers TEXT,
    body_text TEXT,
    body_html TEXT,
    preview TEXT NOT NULL DEFAULT '',
    cjk INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX messages_uid ON messages(folder_id, uid) WHERE uid IS NOT NULL;
CREATE UNIQUE INDEX messages_graph ON messages(graph_id) WHERE graph_id IS NOT NULL;
CREATE UNIQUE INDEX messages_gm ON messages(gm_msgid) WHERE gm_msgid IS NOT NULL;
CREATE INDEX messages_mid ON messages(message_id);
CREATE INDEX messages_thread ON messages(thread_id, date);
CREATE INDEX messages_date ON messages(date DESC);
CREATE INDEX messages_folder_date ON messages(folder_id, date DESC);

CREATE TABLE message_refs(
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    ref TEXT NOT NULL
);
CREATE INDEX message_refs_ref ON message_refs(ref);
CREATE INDEX message_refs_msg ON message_refs(message_id);

CREATE TABLE cjk_grams(
    gram TEXT NOT NULL,
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    PRIMARY KEY(gram, message_id)
) WITHOUT ROWID;
CREATE INDEX cjk_grams_msg ON cjk_grams(message_id);

CREATE TABLE labels(
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    PRIMARY KEY(message_id, label)
) WITHOUT ROWID;
CREATE INDEX labels_label ON labels(label);

CREATE TABLE attachments(
    id INTEGER PRIMARY KEY,
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    mime TEXT NOT NULL,
    size INTEGER NOT NULL,
    content_id TEXT,
    part TEXT NOT NULL,
    blob TEXT
);
CREATE INDEX attachments_msg ON attachments(message_id);

CREATE TABLE outbox(
    id INTEGER PRIMARY KEY,
    message_id TEXT NOT NULL UNIQUE,
    raw BLOB NOT NULL,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_try INTEGER NOT NULL,
    last_error TEXT,
    created INTEGER NOT NULL
);

CREATE TABLE settings_log(
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    value BLOB,
    at INTEGER NOT NULL,
    device TEXT NOT NULL
);

CREATE TABLE undo_log(
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    payload BLOB NOT NULL,
    created INTEGER NOT NULL,
    expires INTEGER NOT NULL
);
CREATE INDEX undo_expires ON undo_log(expires);

CREATE TABLE secrets(
    name TEXT PRIMARY KEY,
    value BLOB NOT NULL
) WITHOUT ROWID;

CREATE VIRTUAL TABLE msg_fts USING fts5(
    subject, from_text, to_text, body_text,
    content='messages', content_rowid='id',
    tokenize='unicode61 remove_diacritics 2', prefix='2 3 4'
);
CREATE VIRTUAL TABLE msg_tri USING fts5(
    subject, from_text, body_text,
    content='messages', content_rowid='id',
    tokenize='trigram'
);

CREATE TRIGGER messages_ai AFTER INSERT ON messages BEGIN
    INSERT INTO msg_fts(rowid, subject, from_text, to_text, body_text)
        VALUES (new.id, new.subject, new.from_text, new.to_text, new.body_text);
    INSERT INTO msg_tri(rowid, subject, from_text, body_text)
        SELECT new.id, new.subject, new.from_text, new.body_text WHERE new.cjk = 1;
END;
CREATE TRIGGER messages_ad AFTER DELETE ON messages BEGIN
    INSERT INTO msg_fts(msg_fts, rowid, subject, from_text, to_text, body_text)
        VALUES ('delete', old.id, old.subject, old.from_text, old.to_text, old.body_text);
    INSERT INTO msg_tri(msg_tri, rowid, subject, from_text, body_text)
        SELECT 'delete', old.id, old.subject, old.from_text, old.body_text WHERE old.cjk = 1;
END;
CREATE TRIGGER messages_au AFTER UPDATE OF subject, from_text, to_text, body_text ON messages BEGIN
    INSERT INTO msg_fts(msg_fts, rowid, subject, from_text, to_text, body_text)
        VALUES ('delete', old.id, old.subject, old.from_text, old.to_text, old.body_text);
    INSERT INTO msg_tri(msg_tri, rowid, subject, from_text, body_text)
        SELECT 'delete', old.id, old.subject, old.from_text, old.body_text WHERE old.cjk = 1;
    INSERT INTO msg_fts(rowid, subject, from_text, to_text, body_text)
        VALUES (new.id, new.subject, new.from_text, new.to_text, new.body_text);
    INSERT INTO msg_tri(rowid, subject, from_text, body_text)
        SELECT new.id, new.subject, new.from_text, new.body_text WHERE new.cjk = 1;
END;
";
