use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine};
use lazymail_graph::Graph;
use lazymail_imap::{BlobRef, Connection, Imap, SETTINGS_FOLDER};
use lazymail_sync::{Error, Folder, Result};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, OnceCell};

use crate::callbacks::Tokens;

/// The folder and subject the settings messages carry, so a person who opens the mailbox sees
/// what they are and does not delete them.
const SUBJECT: &str = "Alazy settings, do not delete";

/// A mailbox's "Alazy" folder for the settings sync, over IMAP or Graph.
pub(crate) enum AccountFolder {
    Imap(ImapFolder),
    Graph(GraphFolder),
}

impl AccountFolder {
    pub(crate) fn imap(imap: Arc<Imap<Tokens>>, address: &str) -> AccountFolder {
        AccountFolder::Imap(ImapFolder {
            imap,
            conn: Mutex::new(None),
            scope: scope(address),
        })
    }

    pub(crate) fn graph(graph: Arc<Graph<Tokens>>, address: &str) -> AccountFolder {
        AccountFolder::Graph(GraphFolder {
            graph,
            folder: OnceCell::new(),
            scope: scope(address),
        })
    }
}

/// Messages are sealed for one scope, so one copied into another account's folder is ignored.
fn scope(address: &str) -> String {
    let d = Sha256::digest(address.trim().to_lowercase().as_bytes());
    d[..8].iter().map(|b| format!("{b:02x}")).collect()
}

fn folder_error(e: impl std::fmt::Display) -> Error {
    Error::Folder(e.to_string())
}

impl Folder for AccountFolder {
    fn scope(&self) -> &str {
        match self {
            AccountFolder::Imap(f) => &f.scope,
            AccountFolder::Graph(f) => &f.scope,
        }
    }

    async fn list(&self) -> Result<Vec<String>> {
        match self {
            AccountFolder::Imap(f) => f.list().await,
            AccountFolder::Graph(f) => f.list().await,
        }
    }

    async fn fetch(&self, id: &str) -> Result<Option<Vec<u8>>> {
        match self {
            AccountFolder::Imap(f) => f.fetch(id).await,
            AccountFolder::Graph(f) => f.fetch(id).await,
        }
    }

    async fn append(&self, body: Vec<u8>) -> Result<String> {
        match self {
            AccountFolder::Imap(f) => f.append(&body).await,
            AccountFolder::Graph(f) => f.append(&body).await,
        }
    }

    async fn delete(&self, id: &str) -> Result<()> {
        match self {
            AccountFolder::Imap(f) => f.delete(id).await,
            AccountFolder::Graph(f) => f.delete(id).await,
        }
    }
}

pub(crate) struct ImapFolder {
    imap: Arc<Imap<Tokens>>,
    /// Kept between calls, since a pull reads the folder message by message.
    conn: Mutex<Option<Connection>>,
    scope: String,
}

impl ImapFolder {
    async fn run<T>(
        &self,
        op: impl AsyncFnOnce(&mut Connection) -> lazymail_imap::Result<T>,
    ) -> Result<T> {
        let mut slot = self.conn.lock().await;
        if slot.is_none() {
            *slot = Some(self.imap.connect().await.map_err(folder_error)?);
        }
        let conn = slot.as_mut().expect("connected above");
        match op(conn).await {
            Ok(v) => Ok(v),
            Err(e) => {
                // The next call starts from a fresh connection.
                *slot = None;
                Err(folder_error(e))
            }
        }
    }

    async fn list(&self) -> Result<Vec<String>> {
        let refs = self
            .run(async |c| c.list_blobs(SETTINGS_FOLDER).await)
            .await?;
        Ok(refs.into_iter().map(id_of).collect())
    }

    async fn fetch(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let Some(at) = parse_id(id) else {
            return Ok(None);
        };
        self.run(async |c| c.fetch_blob(SETTINGS_FOLDER, at).await)
            .await
    }

    async fn append(&self, body: &[u8]) -> Result<String> {
        let message_id = format!("<{}@alazy.invalid>", random_hex());
        let raw = format!(
            "Subject: {SUBJECT}\r\nMessage-ID: {message_id}\r\nMIME-Version: 1.0\r\n\
             Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
            wrapped_base64(body)
        );
        let at = self
            .run(async |c| {
                c.append_blob(SETTINGS_FOLDER, raw.as_bytes(), &message_id)
                    .await
            })
            .await?;
        Ok(id_of(at))
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let Some(at) = parse_id(id) else {
            return Ok(());
        };
        self.run(async |c| c.delete_blob(SETTINGS_FOLDER, at).await)
            .await
    }
}

fn id_of(r: BlobRef) -> String {
    format!("{}:{}", r.validity, r.uid)
}

fn parse_id(id: &str) -> Option<BlobRef> {
    let (validity, uid) = id.split_once(':')?;
    Some(BlobRef {
        validity: validity.parse().ok()?,
        uid: uid.parse().ok()?,
    })
}

fn random_hex() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("system random source");
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn wrapped_base64(data: &[u8]) -> String {
    STANDARD
        .encode(data)
        .as_bytes()
        .chunks(76)
        .map(|l| std::str::from_utf8(l).expect("base64 is ascii"))
        .collect::<Vec<_>>()
        .join("\r\n")
}

pub(crate) struct GraphFolder {
    graph: Arc<Graph<Tokens>>,
    folder: OnceCell<String>,
    scope: String,
}

impl GraphFolder {
    async fn folder(&self) -> Result<&str> {
        self.folder
            .get_or_try_init(|| self.graph.blob_folder(SETTINGS_FOLDER))
            .await
            .map(String::as_str)
            .map_err(folder_error)
    }

    async fn list(&self) -> Result<Vec<String>> {
        let folder = self.folder().await?;
        self.graph.list_blobs(folder).await.map_err(folder_error)
    }

    async fn fetch(&self, id: &str) -> Result<Option<Vec<u8>>> {
        self.graph.fetch_blob(id).await.map_err(folder_error)
    }

    async fn append(&self, body: &[u8]) -> Result<String> {
        let folder = self.folder().await?;
        self.graph
            .append_blob(folder, SUBJECT, body)
            .await
            .map_err(folder_error)
    }

    async fn delete(&self, id: &str) -> Result<()> {
        self.graph.delete_blob(id).await.map_err(folder_error)
    }
}
