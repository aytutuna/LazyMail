mod blobs;
mod crypto;
mod error;
mod folders;
mod logs;
mod messages;
mod outbox;
mod schema;
mod search;
mod secrets;
mod wrap;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::Connection;

pub use error::{Error, Result};
pub use folders::{Folder, SyncState};
pub use logs::{SettingChange, UndoEntry, UNDO_DAYS};
pub use messages::{Attachment, Flags, Message, NewAttachment, NewMessage};
pub use outbox::{OutboxItem, OutboxState};
pub use search::{SearchHit, SearchQuery, MARK_END, MARK_START};
pub use wrap::{load_or_create_key, StoreKey, TestWrapper, Wrapper};

/// One account's encrypted database and attachment files.
pub struct Store {
    conn: Connection,
    dir: PathBuf,
    attachment_key: [u8; 32],
    wrapper: Arc<dyn Wrapper>,
}

impl Store {
    /// Opens or creates the store in `dir`. The wrapper protects the secrets table.
    pub fn open(dir: &Path, key: &StoreKey, wrapper: Arc<dyn Wrapper>) -> Result<Store> {
        std::fs::create_dir_all(dir.join("attachments"))?;
        let conn = Connection::open(dir.join("mail.db"))?;
        conn.pragma_update(None, "key", format!("x'{}'", key.hex()))?;
        if conn
            .query_row("SELECT count(*) FROM sqlite_master", [], |r| {
                r.get::<_, i64>(0)
            })
            .is_err()
        {
            return Err(Error::WrongKey);
        }
        conn.pragma_update(None, "foreign_keys", true)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "cache_size", -16384)?;
        schema::migrate(&conn)?;
        Ok(Store {
            conn,
            dir: dir.to_path_buf(),
            attachment_key: crypto::derive(key.as_bytes(), b"lazymail attachments v1"),
            wrapper,
        })
    }

    /// Runs `f` as one transaction; also nests inside another one.
    pub fn atomic<T>(&self, f: impl FnOnce(&Store) -> Result<T>) -> Result<T> {
        self.conn.execute_batch("SAVEPOINT atomic")?;
        match f(self) {
            Ok(v) => {
                self.conn.execute_batch("RELEASE atomic")?;
                Ok(v)
            }
            Err(e) => {
                self.conn
                    .execute_batch("ROLLBACK TO atomic; RELEASE atomic")?;
                Err(e)
            }
        }
    }

    pub fn schema_version(&self) -> Result<u32> {
        Ok(self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?)
    }
}
