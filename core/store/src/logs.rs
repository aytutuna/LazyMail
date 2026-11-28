use rusqlite::{params, OptionalExtension, Row};

use crate::{Result, Store};

pub const UNDO_DAYS: i64 = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingChange {
    pub seq: i64,
    pub key: String,
    /// None records a removed setting.
    pub value: Option<Vec<u8>>,
    pub at: i64,
    pub device: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoEntry {
    pub id: i64,
    pub kind: String,
    pub payload: Vec<u8>,
    pub created: i64,
    pub expires: i64,
}

fn undo(r: &Row) -> rusqlite::Result<UndoEntry> {
    Ok(UndoEntry {
        id: r.get(0)?,
        kind: r.get(1)?,
        payload: r.get(2)?,
        created: r.get(3)?,
        expires: r.get(4)?,
    })
}

impl Store {
    /// Appends a setting change and returns its sequence number.
    pub fn record_setting(
        &self,
        key: &str,
        value: Option<&[u8]>,
        at: i64,
        device: &str,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO settings_log(key, value, at, device) VALUES (?1, ?2, ?3, ?4)",
            params![key, value, at, device],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Changes after `seq`, in order.
    pub fn settings_since(&self, seq: i64) -> Result<Vec<SettingChange>> {
        let mut st = self.conn.prepare(
            "SELECT seq, key, value, at, device FROM settings_log WHERE seq > ?1 ORDER BY seq",
        )?;
        let rows = st.query_map([seq], |r| {
            Ok(SettingChange {
                seq: r.get(0)?,
                key: r.get(1)?,
                value: r.get(2)?,
                at: r.get(3)?,
                device: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Adds an entry that can be undone for UNDO_DAYS days.
    pub fn push_undo(&self, kind: &str, payload: &[u8], now: i64) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO undo_log(kind, payload, created, expires) VALUES (?1, ?2, ?3, ?4)",
            params![kind, payload, now, now + UNDO_DAYS * 86_400],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Entries that have not expired, newest first.
    pub fn undo_entries(&self, now: i64) -> Result<Vec<UndoEntry>> {
        let mut st = self.conn.prepare(
            "SELECT id, kind, payload, created, expires FROM undo_log
             WHERE expires > ?1 ORDER BY created DESC, id DESC",
        )?;
        let rows = st.query_map([now], undo)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Removes and returns an entry that is being undone.
    pub fn take_undo(&self, id: i64, now: i64) -> Result<Option<UndoEntry>> {
        self.atomic(|s| {
            let e = s
                .conn
                .query_row(
                    "SELECT id, kind, payload, created, expires FROM undo_log WHERE id = ?1 AND expires > ?2",
                    params![id, now],
                    undo,
                )
                .optional()?;
            if e.is_some() {
                s.conn.execute("DELETE FROM undo_log WHERE id = ?1", [id])?;
            }
            Ok(e)
        })
    }

    pub fn purge_undo(&self, now: i64) -> Result<usize> {
        Ok(self
            .conn
            .execute("DELETE FROM undo_log WHERE expires <= ?1", [now])?)
    }
}
