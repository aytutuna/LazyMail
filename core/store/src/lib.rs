mod blobs;
mod cjk;
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

use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::{Connection, ErrorCode};
use zeroize::Zeroizing;

pub use error::{Error, Result};
pub use folders::{Folder, SyncState};
pub use logs::{SettingChange, UndoEntry, UNDO_DAYS};
pub use messages::{Attachment, Flags, Message, NewAttachment, NewMessage};
pub use outbox::{OutboxItem, OutboxState};
pub use search::{SearchHit, SearchQuery, MARK_END, MARK_START};
#[cfg(feature = "test-wrapper")]
pub use wrap::TestWrapper;
pub use wrap::{load_or_create_key, StoreKey, Wrapper};

/// One account's encrypted database and attachment files.
pub struct Store {
    conn: Connection,
    dir: PathBuf,
    attachment_key: Zeroizing<[u8; 32]>,
    wrapper: Arc<dyn Wrapper>,
    /// Open `atomic` calls.
    depth: Cell<u32>,
    /// Attachment files to delete once the outermost transaction has committed.
    doomed: RefCell<Vec<String>>,
}

impl Store {
    /// Opens or creates the store in `dir`. The wrapper protects the secrets table.
    pub fn open(dir: &Path, key: &StoreKey, wrapper: Arc<dyn Wrapper>) -> Result<Store> {
        std::fs::create_dir_all(dir.join("attachments"))?;
        let conn = Connection::open(dir.join("mail.db"))?;
        conn.pragma_update(
            None,
            "key",
            Zeroizing::new(format!("x'{}'", *key.hex())).as_str(),
        )?;
        match conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        }) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == ErrorCode::NotADatabase => {
                return Err(Error::WrongKey)
            }
            Err(e) => return Err(e.into()),
        }
        conn.pragma_update(None, "foreign_keys", true)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "cache_size", -16384)?;
        schema::migrate(&conn)?;
        let store = Store {
            conn,
            dir: dir.to_path_buf(),
            attachment_key: Zeroizing::new(crypto::derive(
                key.as_bytes(),
                b"lazymail attachments v1",
            )),
            wrapper,
            depth: Cell::new(0),
            doomed: RefCell::new(Vec::new()),
        };
        store.sweep_attachments()?;
        Ok(store)
    }

    /// Runs `f` as one transaction; also nests inside another one.
    pub fn atomic<T>(&self, f: impl FnOnce(&Store) -> Result<T>) -> Result<T> {
        self.conn.execute_batch("SAVEPOINT atomic")?;
        let mark = self.doomed.borrow().len();
        self.depth.set(self.depth.get() + 1);
        let out = f(self).and_then(|v| {
            self.conn.execute_batch("RELEASE atomic")?;
            Ok(v)
        });
        self.depth.set(self.depth.get() - 1);
        match out {
            Ok(v) => {
                if self.depth.get() == 0 {
                    self.remove_doomed();
                }
                Ok(v)
            }
            Err(e) => {
                self.doomed.borrow_mut().truncate(mark);
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
