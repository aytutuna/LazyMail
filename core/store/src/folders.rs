use rusqlite::{params, OptionalExtension, Row};

use crate::{Result, Store};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncState {
    pub uidvalidity: Option<u32>,
    pub uidnext: Option<u32>,
    pub highestmodseq: Option<i64>,
    pub delta_link: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    pub id: i64,
    pub name: String,
    /// Special-use role such as "inbox", "sent" or "trash".
    pub role: Option<String>,
    pub sync: SyncState,
}

fn folder(r: &Row) -> rusqlite::Result<Folder> {
    Ok(Folder {
        id: r.get(0)?,
        name: r.get(1)?,
        role: r.get(2)?,
        sync: SyncState {
            uidvalidity: r.get(3)?,
            uidnext: r.get(4)?,
            highestmodseq: r.get(5)?,
            delta_link: r.get(6)?,
        },
    })
}

const COLS: &str = "id, name, role, uidvalidity, uidnext, highestmodseq, delta_link";

impl Store {
    /// Returns the folder called `name`, creating it if needed. The role is updated when given.
    pub fn upsert_folder(&self, name: &str, role: Option<&str>) -> Result<Folder> {
        self.conn.execute(
            "INSERT INTO folders(name, role) VALUES (?1, ?2)
             ON CONFLICT(name) DO UPDATE SET role = coalesce(?2, role)",
            params![name, role],
        )?;
        self.conn
            .query_row(
                &format!("SELECT {COLS} FROM folders WHERE name = ?1"),
                [name],
                folder,
            )
            .map_err(Into::into)
    }

    pub fn folders(&self) -> Result<Vec<Folder>> {
        let mut st = self
            .conn
            .prepare(&format!("SELECT {COLS} FROM folders ORDER BY name"))?;
        let rows = st.query_map([], folder)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn folder(&self, id: i64) -> Result<Option<Folder>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {COLS} FROM folders WHERE id = ?1"),
                [id],
                folder,
            )
            .optional()?)
    }

    pub fn set_sync_state(&self, id: i64, s: &SyncState) -> Result<()> {
        self.conn.execute(
            "UPDATE folders SET uidvalidity = ?2, uidnext = ?3, highestmodseq = ?4, delta_link = ?5
             WHERE id = ?1",
            params![id, s.uidvalidity, s.uidnext, s.highestmodseq, s.delta_link],
        )?;
        Ok(())
    }

    /// Drops every message of the folder and its sync state, for a changed UIDVALIDITY or an
    /// expired delta link.
    pub fn reset_folder(&self, id: i64) -> Result<()> {
        self.atomic(|s| {
            let ids: Vec<i64> = s
                .conn
                .prepare("SELECT id FROM messages WHERE folder_id = ?1")?
                .query_map([id], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            for m in ids {
                s.delete_message(m)?;
            }
            s.set_sync_state(id, &SyncState::default())
        })
    }

    pub fn remove_folder(&self, id: i64) -> Result<()> {
        self.atomic(|s| {
            s.reset_folder(id)?;
            s.conn.execute("DELETE FROM folders WHERE id = ?1", [id])?;
            Ok(())
        })
    }
}
