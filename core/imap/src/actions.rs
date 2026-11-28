use std::sync::Mutex;

use lazymail_store::{Flags, Store};
use serde::{Deserialize, Serialize};

use crate::conn::{quote, Connection};
use crate::error::{Error, Result};
use crate::sync::fetch_part;
use crate::utf7;

/// Where a moved or appended message landed, when the server said (COPYUID or APPENDUID).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placed {
    pub uidvalidity: u32,
    pub uid: u32,
}

/// What Undo needs to put a moved message back: kept in the store's undo log as JSON under
/// the kind "imap-move".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveUndo {
    pub message_id: i64,
    /// The Message-ID header, to find the message again when the row or its UID is gone.
    pub rfc_message_id: Option<String>,
    pub from_folder: i64,
    pub from_uidvalidity: Option<u32>,
    pub from_uid: u32,
    pub to_folder: i64,
    /// Both None when the server gave no COPYUID.
    pub to_uidvalidity: Option<u32>,
    pub to_uid: Option<u32>,
}

struct Located {
    folder_id: i64,
    uidvalidity: Option<u32>,
    rfc_message_id: Option<String>,
    folder: String,
    uid: u32,
    flags: Flags,
}

fn locate(store: &Mutex<Store>, message_id: i64) -> Result<Located> {
    let s = store.lock().unwrap();
    let m = s
        .message(message_id)?
        .ok_or(lazymail_store::Error::NotFound)?;
    let uid = m
        .uid
        .ok_or_else(|| Error::Protocol("the message has no UID yet".into()))?;
    let folder = s
        .folder(m.folder_id)?
        .ok_or(lazymail_store::Error::NotFound)?;
    Ok(Located {
        folder_id: m.folder_id,
        uidvalidity: folder.sync.uidvalidity,
        rfc_message_id: m.message_id,
        folder: folder.name,
        uid,
        flags: m.flags,
    })
}

fn names(f: Flags) -> Vec<&'static str> {
    let mut v = Vec::new();
    if f.seen {
        v.push("\\Seen");
    }
    if f.flagged {
        v.push("\\Flagged");
    }
    if f.answered {
        v.push("\\Answered");
    }
    if f.draft {
        v.push("\\Draft");
    }
    if f.deleted {
        v.push("\\Deleted");
    }
    v
}

impl Connection {
    /// Sets the standard flags of a stored message, touching only the flags that differ so
    /// keywords the app does not know about stay.
    pub async fn set_flags(
        &mut self,
        store: &Mutex<Store>,
        message_id: i64,
        flags: Flags,
    ) -> Result<()> {
        let at = locate(store, message_id)?;
        let add: Vec<&str> = names(flags)
            .into_iter()
            .filter(|n| !names(at.flags).contains(n))
            .collect();
        let remove: Vec<&str> = names(at.flags)
            .into_iter()
            .filter(|n| !names(flags).contains(n))
            .collect();
        if !add.is_empty() || !remove.is_empty() {
            self.ensure(&at.folder).await?;
            if !add.is_empty() {
                self.exec(&format!(
                    "UID STORE {} +FLAGS.SILENT ({})",
                    at.uid,
                    add.join(" ")
                ))
                .await?;
            }
            if !remove.is_empty() {
                self.exec(&format!(
                    "UID STORE {} -FLAGS.SILENT ({})",
                    at.uid,
                    remove.join(" ")
                ))
                .await?;
            }
        }
        store.lock().unwrap().set_flags(message_id, flags)?;
        Ok(())
    }

    /// Moves a message to another stored folder, with MOVE when the server has it and COPY,
    /// \Deleted and EXPUNGE otherwise. The row keeps its id, thread and attachments, and the
    /// move goes to the undo log, with the new UID when the server reports it.
    pub async fn move_message(
        &mut self,
        store: &Mutex<Store>,
        message_id: i64,
        to_folder: i64,
        now: i64,
    ) -> Result<Option<Placed>> {
        let at = locate(store, message_id)?;
        let to = store
            .lock()
            .unwrap()
            .folder(to_folder)?
            .ok_or(lazymail_store::Error::NotFound)?;
        self.ensure(&at.folder).await?;
        let dest = quote(&utf7::encode(&to.name))?;
        let reply = if self.caps.move_ {
            self.exec(&format!("UID MOVE {} {dest}", at.uid)).await?
        } else {
            self.check_expungeable(at.uid).await?;
            let reply = self.exec(&format!("UID COPY {} {dest}", at.uid)).await?;
            self.expunge(at.uid).await?;
            reply
        };
        let moved = reply.copy_uid.and_then(|m| {
            m.first.map(|uid| Placed {
                uidvalidity: m.validity,
                uid,
            })
        });
        let s = store.lock().unwrap();
        // Without a UID the row waits in the new folder and takes the UID the next sync of that
        // folder finds under the same Message-ID.
        s.move_message(message_id, to_folder, moved.map(|m| m.uid))?;
        let undo = MoveUndo {
            message_id,
            rfc_message_id: at.rfc_message_id,
            from_folder: at.folder_id,
            from_uidvalidity: at.uidvalidity,
            from_uid: at.uid,
            to_folder,
            to_uidvalidity: moved.map(|m| m.uidvalidity),
            to_uid: moved.map(|m| m.uid),
        };
        let payload = serde_json::to_vec(&undo).expect("plain data serializes");
        s.push_undo("imap-move", &payload, now)?;
        Ok(moved)
    }

    /// Deletes a message for good, on the server and in the store.
    pub async fn delete_message(&mut self, store: &Mutex<Store>, message_id: i64) -> Result<()> {
        let at = locate(store, message_id)?;
        self.ensure(&at.folder).await?;
        self.check_expungeable(at.uid).await?;
        self.expunge(at.uid).await?;
        store.lock().unwrap().delete_message(message_id)?;
        Ok(())
    }

    // Plain EXPUNGE takes every message that carries \Deleted, so without UIDPLUS it can run
    // only when this is the only one. Asked before a COPY, so a refusal leaves nothing behind.
    async fn check_expungeable(&mut self, uid: u32) -> Result<()> {
        if !self.caps.uidplus {
            let marked = self.uid_search("DELETED").await?;
            if marked.iter().any(|u| *u != uid) {
                return Err(Error::Refused(
                    "other messages in the folder are marked deleted".into(),
                ));
            }
        }
        Ok(())
    }

    // Marks one message \Deleted and removes it.
    async fn expunge(&mut self, uid: u32) -> Result<()> {
        self.exec(&format!("UID STORE {uid} +FLAGS.SILENT (\\Deleted)"))
            .await?;
        if self.caps.uidplus {
            self.exec(&format!("UID EXPUNGE {uid}")).await?;
        } else {
            self.exec("EXPUNGE").await?;
        }
        Ok(())
    }

    pub async fn create_folder(&mut self, name: &str) -> Result<()> {
        self.exec(&format!("CREATE {}", quote(&utf7::encode(name))?))
            .await
            .map(drop)
    }

    /// Adds a message to a folder. The new UID is returned when the server reports it.
    pub async fn append_message(
        &mut self,
        folder: &str,
        message: &[u8],
        flags: Flags,
    ) -> Result<Option<Placed>> {
        let reply = self
            .append(folder, &names(flags).join(" "), message)
            .await?;
        Ok(reply
            .append_uid
            .map(|(uidvalidity, uid)| Placed { uidvalidity, uid }))
    }

    /// UIDs in a folder whose Message-ID header holds `message_id`; the SMTP step uses this
    /// to see whether a sent message has already been filed.
    pub async fn find_by_message_id(&mut self, folder: &str, message_id: &str) -> Result<Vec<u32>> {
        self.select(folder).await?;
        let id = message_id.trim().trim_matches(['<', '>']);
        self.uid_search(&format!("HEADER Message-ID {}", quote(id)?))
            .await
    }

    /// Downloads one attachment of a stored message, keeps it in the file store and returns it.
    pub async fn download_attachment(
        &mut self,
        store: &Mutex<Store>,
        message_id: i64,
        attachment_id: i64,
    ) -> Result<Vec<u8>> {
        if let Some(data) = store.lock().unwrap().attachment_data(attachment_id)? {
            return Ok(data);
        }
        let part = {
            let s = store.lock().unwrap();
            let m = s
                .message(message_id)?
                .ok_or(lazymail_store::Error::NotFound)?;
            m.attachments
                .into_iter()
                .find(|a| a.id == attachment_id)
                .ok_or(lazymail_store::Error::NotFound)?
                .part
        };
        let at = locate(store, message_id)?;
        let data = fetch_part(self, &at.folder, at.uid, &part).await?;
        store
            .lock()
            .unwrap()
            .put_attachment_data(attachment_id, &data)?;
        Ok(data)
    }
}
