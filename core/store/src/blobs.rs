use std::collections::HashSet;
use std::path::PathBuf;

use rusqlite::{params, OptionalExtension};

use crate::wrap::write_durably;
use crate::{crypto, Error, Result, Store};

const SWEEP_GRACE: std::time::Duration = std::time::Duration::from_secs(600);

impl Store {
    fn blob_path(&self, name: &str) -> PathBuf {
        self.dir.join("attachments").join(name)
    }

    /// Deletes a file now, or after the outermost transaction commits so that a rollback
    /// never leaves a row pointing at a missing file.
    pub(crate) fn drop_blob(&self, name: String) {
        if self.depth.get() == 0 {
            let _ = std::fs::remove_file(self.blob_path(&name));
        } else {
            self.doomed.borrow_mut().push(name);
        }
    }

    pub(crate) fn remove_doomed(&self) {
        for name in self.doomed.take() {
            let _ = std::fs::remove_file(self.blob_path(&name));
        }
    }

    /// Removes files no row refers to: leftovers of a crash or a rolled back write. A file from
    /// the last few minutes may belong to a write another open store has not committed yet.
    pub(crate) fn sweep_attachments(&self) -> Result<()> {
        let known: HashSet<String> = self
            .conn
            .prepare("SELECT blob FROM attachments WHERE blob IS NOT NULL")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for entry in std::fs::read_dir(self.dir.join("attachments"))? {
            let entry = entry?;
            let fresh = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age < SWEEP_GRACE);
            if !fresh && !known.contains(entry.file_name().to_string_lossy().as_ref()) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        Ok(())
    }

    /// Stores the bytes of an attachment, replacing any earlier copy.
    pub fn put_attachment_data(&self, attachment_id: i64, data: &[u8]) -> Result<()> {
        let old: Option<String> = self
            .conn
            .query_row(
                "SELECT blob FROM attachments WHERE id = ?1",
                [attachment_id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        let name: String = crypto::random::<16>()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        write_durably(
            &self.blob_path(&name),
            &crypto::seal(&self.attachment_key, name.as_bytes(), data),
        )?;
        self.conn.execute(
            "UPDATE attachments SET blob = ?2 WHERE id = ?1",
            params![attachment_id, name],
        )?;
        if let Some(old) = old {
            self.drop_blob(old);
        }
        Ok(())
    }

    /// Returns the bytes, or None when the attachment was never downloaded, was evicted or its
    /// file has gone missing (the caller downloads it again).
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
        match std::fs::read(self.blob_path(&name)) {
            Ok(data) => crypto::open(&self.attachment_key, name.as_bytes(), &data).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.conn.execute(
                    "UPDATE attachments SET blob = NULL WHERE id = ?1",
                    [attachment_id],
                )?;
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
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
            self.drop_blob(n);
        }
        Ok(())
    }
}
