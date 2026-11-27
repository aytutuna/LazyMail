use std::path::PathBuf;

use rusqlite::{params, OptionalExtension};

use crate::{crypto, Error, Result, Store};

impl Store {
    fn blob_path(&self, name: &str) -> PathBuf {
        self.dir.join("attachments").join(name)
    }

    /// Stores the bytes of an attachment, replacing any earlier copy.
    pub fn put_attachment_data(&self, attachment_id: i64, data: &[u8]) -> Result<()> {
        let name: String = crypto::random::<16>()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let path = self.blob_path(&name);
        let tmp = path.with_extension("tmp");
        std::fs::write(
            &tmp,
            crypto::seal(&self.attachment_key, name.as_bytes(), data),
        )?;
        std::fs::rename(&tmp, &path)?;
        let old: Option<String> = self
            .conn
            .query_row(
                "SELECT blob FROM attachments WHERE id = ?1",
                [attachment_id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        self.conn.execute(
            "UPDATE attachments SET blob = ?2 WHERE id = ?1",
            params![attachment_id, name],
        )?;
        if let Some(old) = old {
            let _ = std::fs::remove_file(self.blob_path(&old));
        }
        Ok(())
    }

    /// Returns the bytes, or None when the attachment was never downloaded or was evicted.
    pub fn attachment_data(&self, attachment_id: i64) -> Result<Option<Vec<u8>>> {
        let name: Option<String> = self
            .conn
            .query_row(
                "SELECT blob FROM attachments WHERE id = ?1",
                [attachment_id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        let Some(name) = name else { return Ok(None) };
        let data = std::fs::read(self.blob_path(&name))?;
        crypto::open(&self.attachment_key, name.as_bytes(), &data).map(Some)
    }

    /// Removes the downloaded copy of one attachment; the metadata stays.
    pub fn evict_attachment(&self, attachment_id: i64) -> Result<()> {
        self.evict("id = ?1", attachment_id)
    }

    pub(crate) fn evict_message_attachments(&self, message_id: i64) -> Result<()> {
        self.evict("message_id = ?1", message_id)
    }

    fn evict(&self, filter: &str, arg: i64) -> Result<()> {
        let names: Vec<String> = self
            .conn
            .prepare(&format!(
                "SELECT blob FROM attachments WHERE blob IS NOT NULL AND {filter}"
            ))?
            .query_map([arg], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        self.conn.execute(
            &format!("UPDATE attachments SET blob = NULL WHERE {filter}"),
            [arg],
        )?;
        for n in names {
            let _ = std::fs::remove_file(self.blob_path(&n));
        }
        Ok(())
    }
}
