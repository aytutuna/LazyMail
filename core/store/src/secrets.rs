use rusqlite::{params, OptionalExtension};

use crate::{Result, Store};

impl Store {
    /// Keeps a token, password or key encrypted with the device wrapping key.
    pub fn set_secret(&self, name: &str, value: &[u8]) -> Result<()> {
        let wrapped = self.wrapper.wrap(value)?;
        self.conn.execute(
            "INSERT INTO secrets(name, value) VALUES (?1, ?2)
             ON CONFLICT(name) DO UPDATE SET value = ?2",
            params![name, wrapped],
        )?;
        Ok(())
    }

    pub fn secret(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let wrapped: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT value FROM secrets WHERE name = ?1", [name], |r| {
                r.get(0)
            })
            .optional()?;
        wrapped.map(|w| self.wrapper.unwrap(&w)).transpose()
    }

    pub fn delete_secret(&self, name: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM secrets WHERE name = ?1", [name])?;
        Ok(())
    }

    pub fn secret_names(&self) -> Result<Vec<String>> {
        let mut st = self
            .conn
            .prepare("SELECT name FROM secrets ORDER BY name")?;
        let rows = st.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}
