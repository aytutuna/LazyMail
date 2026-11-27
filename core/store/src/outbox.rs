use rusqlite::{params, OptionalExtension, Row};

use crate::{Error, Result, Store};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxState {
    Queued,
    Sending,
    /// Gave up after a permanent error; waits for the person to retry or remove it.
    Failed,
    Sent,
}

impl OutboxState {
    fn parse(s: &str) -> OutboxState {
        match s {
            "sending" => OutboxState::Sending,
            "failed" => OutboxState::Failed,
            "sent" => OutboxState::Sent,
            _ => OutboxState::Queued,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxItem {
    pub id: i64,
    /// Fixed when queued, so a retry after a lost reply never sends a second message.
    pub message_id: String,
    pub raw: Vec<u8>,
    pub state: OutboxState,
    pub attempts: u32,
    pub next_try: i64,
    pub last_error: Option<String>,
    pub created: i64,
}

const COLS: &str = "id, message_id, raw, state, attempts, next_try, last_error, created";

fn item(r: &Row) -> rusqlite::Result<OutboxItem> {
    Ok(OutboxItem {
        id: r.get(0)?,
        message_id: r.get(1)?,
        raw: r.get(2)?,
        state: OutboxState::parse(&r.get::<_, String>(3)?),
        attempts: r.get(4)?,
        next_try: r.get(5)?,
        last_error: r.get(6)?,
        created: r.get(7)?,
    })
}

impl Store {
    pub fn outbox_enqueue(&self, message_id: &str, raw: &[u8], now: i64) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO outbox(message_id, raw, state, next_try, created) VALUES (?1, ?2, 'queued', ?3, ?3)",
            params![message_id, raw, now],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn outbox_item(&self, id: i64) -> Result<Option<OutboxItem>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {COLS} FROM outbox WHERE id = ?1"),
                [id],
                item,
            )
            .optional()?)
    }

    pub fn outbox_list(&self) -> Result<Vec<OutboxItem>> {
        let mut st = self
            .conn
            .prepare(&format!("SELECT {COLS} FROM outbox ORDER BY created, id"))?;
        let rows = st.query_map([], item)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Queued items whose time has come, oldest first.
    pub fn outbox_due(&self, now: i64) -> Result<Vec<OutboxItem>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {COLS} FROM outbox WHERE state = 'queued' AND next_try <= ?1 ORDER BY next_try, id"
        ))?;
        let rows = st.query_map([now], item)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn outbox_begin_send(&self, id: i64) -> Result<()> {
        self.set_state(id, "sending")
    }

    pub fn outbox_mark_sent(&self, id: i64) -> Result<()> {
        self.set_state(id, "sent")
    }

    /// Records a failed attempt. With a time the item is queued again then; without one it is
    /// parked as Failed.
    pub fn outbox_fail(&self, id: i64, error: &str, retry_at: Option<i64>) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE outbox SET attempts = attempts + 1, last_error = ?2,
                 state = CASE WHEN ?3 IS NULL THEN 'failed' ELSE 'queued' END,
                 next_try = coalesce(?3, next_try)
             WHERE id = ?1",
            params![id, error, retry_at],
        )?;
        if n == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    pub fn outbox_requeue(&self, id: i64, at: i64) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE outbox SET state = 'queued', next_try = ?2 WHERE id = ?1",
            params![id, at],
        )?;
        if n == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// Items left in Sending by a crash go back to the queue. Whether the server took them is
    /// unknown, which is why the Message-ID stays fixed.
    pub fn outbox_requeue_interrupted(&self, now: i64) -> Result<usize> {
        Ok(self.conn.execute(
            "UPDATE outbox SET state = 'queued', next_try = ?1 WHERE state = 'sending'",
            [now],
        )?)
    }

    pub fn outbox_remove(&self, id: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM outbox WHERE id = ?1", [id])?;
        Ok(())
    }

    fn set_state(&self, id: i64, state: &str) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE outbox SET state = ?2 WHERE id = ?1",
            params![id, state],
        )?;
        if n == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }
}
