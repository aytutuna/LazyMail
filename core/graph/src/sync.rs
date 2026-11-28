use std::collections::HashSet;
use std::ops::AddAssign;

use lazymail_accounts::TokenSource;
use lazymail_store::{Flags, Folder, NewMessage, Store, SyncState};
use mail_parser::DateTime;
use serde::Deserialize;

use crate::client::{Error, Graph, Result};
use crate::mime;

/// The folder list's delta link has no folder row to live in.
const FOLDER_DELTA: &str = "graph-folders-delta";

/// Graph's well-known folder names and the roles the store uses.
const ROLES: [(&str, &str); 6] = [
    ("inbox", "inbox"),
    ("sentitems", "sent"),
    ("drafts", "drafts"),
    ("deleteditems", "trash"),
    ("junkemail", "junk"),
    ("archive", "archive"),
];

const MESSAGE_FIELDS: &str =
    "internetMessageId,subject,from,toRecipients,ccRecipients,receivedDateTime,isRead,isDraft,flag";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
}

/// What a full `sync` did. A folder that failed with an error of its own (gone, refused, an
/// answer that makes no sense) is listed in `failed` and the others still sync; sign-in,
/// throttling and network errors end the run instead, since every folder would fail alike.
#[derive(Debug, Default)]
pub struct SyncReport {
    pub summary: Summary,
    /// Folder id and what it changed, in the order they finished (Inbox first).
    pub folders: Vec<(i64, Summary)>,
    pub failed: Vec<(i64, Error)>,
}

impl AddAssign for Summary {
    fn add_assign(&mut self, o: Summary) {
        self.added += o.added;
        self.updated += o.updated;
        self.removed += o.removed;
    }
}

#[derive(Deserialize)]
struct Page<T> {
    value: Vec<T>,
    #[serde(rename = "@odata.nextLink")]
    next: Option<String>,
    #[serde(rename = "@odata.deltaLink")]
    delta: Option<String>,
}

#[derive(Deserialize)]
struct FolderItem {
    id: String,
    #[serde(rename = "displayName", default)]
    name: String,
    #[serde(rename = "@removed")]
    removed: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageItem {
    id: String,
    #[serde(rename = "@removed")]
    removed: Option<serde_json::Value>,
    internet_message_id: Option<String>,
    #[serde(default)]
    subject: String,
    from: Option<Recipient>,
    #[serde(default)]
    to_recipients: Vec<Recipient>,
    #[serde(default)]
    cc_recipients: Vec<Recipient>,
    received_date_time: Option<String>,
    #[serde(default)]
    is_read: bool,
    #[serde(default)]
    is_draft: bool,
    flag: Option<FlagState>,
}

#[derive(Deserialize)]
struct Recipient {
    #[serde(rename = "emailAddress")]
    address: EmailAddress,
}

#[derive(Deserialize)]
struct EmailAddress {
    #[serde(default)]
    name: String,
    #[serde(default)]
    address: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FlagState {
    flag_status: String,
}

impl MessageItem {
    fn flags(&self) -> Flags {
        Flags {
            seen: self.is_read,
            flagged: self
                .flag
                .as_ref()
                .is_some_and(|f| f.flag_status == "flagged"),
            draft: self.is_draft,
            ..Flags::default()
        }
    }

    fn new_message(
        &self,
        folder_id: i64,
        size: usize,
        parsed: Option<&mime::Parsed>,
    ) -> NewMessage {
        let from = self.from.as_ref().map(|r| &r.address);
        NewMessage {
            folder_id,
            graph_id: Some(self.id.clone()),
            message_id: self
                .internet_message_id
                .as_deref()
                .map(|m| m.trim_matches(['<', '>']).to_string()),
            subject: self.subject.clone(),
            from_name: from.map(|a| a.name.clone()).unwrap_or_default(),
            from_addr: from.map(|a| a.address.clone()).unwrap_or_default(),
            to: display(&self.to_recipients),
            cc: display(&self.cc_recipients),
            date: self
                .received_date_time
                .as_deref()
                .and_then(DateTime::parse_rfc3339)
                .map_or(0, |d| d.to_timestamp()),
            size: size as u32,
            flags: self.flags(),
            in_reply_to: parsed.and_then(|p| p.in_reply_to.clone()),
            references: parsed.map(|p| p.references.clone()).unwrap_or_default(),
            headers: parsed.map(|p| p.headers.clone()),
            body_text: parsed.and_then(|p| p.text.clone()),
            body_html: parsed.and_then(|p| p.html.clone()),
            attachments: parsed.map(|p| p.attachments.clone()).unwrap_or_default(),
            ..NewMessage::default()
        }
    }
}

fn display(list: &[Recipient]) -> String {
    list.iter()
        .map(|r| {
            let a = &r.address;
            if a.name.is_empty() || a.name == a.address {
                a.address.clone()
            } else {
                format!("{} <{}>", a.name, a.address)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

impl<T: TokenSource> Graph<T> {
    /// Brings the folder list and every folder's messages up to date.
    pub async fn sync(&self, store: &Store) -> Result<SyncReport> {
        self.sync_folders(store).await?;
        let mut folders = store.folders()?;
        folders.sort_by_key(|f| f.role.as_deref() != Some("inbox"));
        let mut report = SyncReport::default();
        for folder in folders {
            if folder.remote_id.is_none() {
                continue;
            }
            match self.sync_folder(store, folder.id).await {
                Ok(sum) => {
                    report.summary += sum;
                    report.folders.push((folder.id, sum));
                }
                Err(e @ (Error::Api { .. } | Error::NotFound | Error::BadResponse(_))) => {
                    report.failed.push((folder.id, e));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(report)
    }

    /// Follows the folder delta, remembering where it stopped.
    pub async fn sync_folders(&self, store: &Store) -> Result<()> {
        let saved = store
            .secret(FOLDER_DELTA)?
            .and_then(|b| String::from_utf8(b).ok());
        match self.folder_pages(store, saved.as_deref()).await {
            Err(Error::SyncStateGone) if saved.is_some() => {
                store.delete_secret(FOLDER_DELTA)?;
                self.folder_pages(store, None).await
            }
            r => r,
        }
    }

    async fn folder_pages(&self, store: &Store, from: Option<&str>) -> Result<()> {
        let full = from.is_none();
        let mut url = match from {
            Some(link) => self.link(link)?,
            None => self.url(
                &["me", "mailFolders", "delta"],
                &[("$select", "displayName")],
            ),
        };
        let mut seen = HashSet::new();
        let mut changed = false;
        loop {
            let page: Page<FolderItem> = self.get_json(url).await?;
            let resume = page
                .next
                .as_deref()
                .or(page.delta.as_deref())
                .ok_or_else(|| Error::BadResponse("page without a link".into()))?;
            store.atomic(|s| {
                for item in &page.value {
                    if item.removed.is_some() {
                        let known = s
                            .folders()?
                            .into_iter()
                            .find(|f| f.remote_id.as_deref() == Some(&item.id));
                        if let Some(f) = known {
                            s.remove_folder(f.id)?;
                            changed = true;
                        }
                    } else {
                        s.upsert_remote_folder(&item.id, &item.name, None)?;
                        seen.insert(item.id.clone());
                        changed = true;
                    }
                }
                s.set_secret(FOLDER_DELTA, resume.as_bytes())
            })?;
            match &page.next {
                Some(next) => url = self.link(next)?,
                None => break,
            }
        }
        if full {
            for f in store.folders()? {
                if f.remote_id.as_ref().is_some_and(|r| !seen.contains(r)) {
                    store.remove_folder(f.id)?;
                }
            }
        }
        if changed {
            self.resolve_roles(store).await?;
        }
        Ok(())
    }

    async fn resolve_roles(&self, store: &Store) -> Result<()> {
        #[derive(Deserialize)]
        struct Id {
            id: String,
        }
        for (well_known, role) in ROLES {
            let url = self.url(&["me", "mailFolders", well_known], &[("$select", "id")]);
            let id = match self.get_json::<Id>(url).await {
                Ok(f) => f.id,
                // An archive folder exists only once the person has made one.
                Err(Error::NotFound) => continue,
                Err(e) => return Err(e),
            };
            let known = store
                .folders()?
                .into_iter()
                .find(|f| f.remote_id.as_deref() == Some(&id));
            if let Some(f) = known {
                store.upsert_remote_folder(&id, &f.name, Some(role))?;
            }
        }
        Ok(())
    }

    /// Downloads what changed in one folder since the last sync. A first sync, or one after the
    /// server dropped the delta link, fetches every message.
    pub async fn sync_folder(&self, store: &Store, folder_id: i64) -> Result<Summary> {
        let folder = store.folder(folder_id)?.ok_or(Error::NotFound)?;
        let saved = folder.sync.delta_link.clone();
        match self.message_pages(store, &folder, saved.as_deref()).await {
            Err(Error::SyncStateGone) if saved.is_some() => {
                store.reset_folder(folder.id)?;
                self.message_pages(store, &folder, None).await
            }
            r => r,
        }
    }

    async fn message_pages(
        &self,
        store: &Store,
        folder: &Folder,
        from: Option<&str>,
    ) -> Result<Summary> {
        let remote = folder.remote_id.as_deref().ok_or(Error::NotFound)?;
        let mut url = match from {
            Some(link) => self.link(link)?,
            None => self.url(
                &["me", "mailFolders", remote, "messages", "delta"],
                &[("$select", MESSAGE_FIELDS)],
            ),
        };
        let mut total = Summary::default();
        loop {
            let page: Page<MessageItem> = self.get_json(url).await?;
            let resume = page
                .next
                .clone()
                .or_else(|| page.delta.clone())
                .ok_or_else(|| Error::BadResponse("page without a link".into()))?;
            // One message at a time, so a page of large mail is never held in memory and an
            // interrupted run keeps what it fetched.
            for item in &page.value {
                let mut raw = None;
                if item.removed.is_none() && store.find_by_graph_id(&item.id)?.is_none() {
                    match self.mime(&item.id).await {
                        Ok(b) => raw = Some(b),
                        // Gone since the delta was made; the next delta says so.
                        Err(Error::NotFound) => continue,
                        Err(e) => return Err(e),
                    }
                }
                total += store.atomic(|s| apply(s, folder.id, item, raw.as_deref()))?;
            }
            store.set_sync_state(
                folder.id,
                &SyncState {
                    delta_link: Some(resume),
                    ..SyncState::default()
                },
            )?;
            match page.next {
                Some(next) => url = self.link(&next)?,
                None => return Ok(total),
            }
        }
    }

    async fn mime(&self, graph_id: &str) -> Result<Vec<u8>> {
        let url = self.url(&["me", "messages", graph_id, "$value"], &[]);
        let resp = self.send(|c| c.get(url.clone())).await?;
        Ok(resp.bytes().await?.to_vec())
    }
}

fn apply(
    s: &Store,
    folder_id: i64,
    item: &MessageItem,
    raw: Option<&[u8]>,
) -> lazymail_store::Result<Summary> {
    let mut sum = Summary::default();
    let existing = s.find_by_graph_id(&item.id)?;
    if item.removed.is_some() {
        // A message moved to another folder shows up as removed here, and the other folder's
        // delta may have been read first.
        if let Some(id) = existing {
            if s.message(id)?.is_some_and(|m| m.folder_id == folder_id) {
                s.delete_message(id)?;
                sum.removed += 1;
            }
        }
    } else if let Some(id) = existing {
        let Some(m) = s.message(id)? else {
            return Ok(sum);
        };
        let new = item.flags();
        let flags = Flags {
            seen: new.seen,
            flagged: new.flagged,
            draft: new.draft,
            ..m.flags
        };
        let moved = m.folder_id != folder_id;
        if moved {
            s.move_message(id, folder_id, None)?;
        }
        if flags != m.flags {
            s.set_flags(id, flags)?;
        }
        if moved || flags != m.flags {
            sum.updated += 1;
        }
    } else {
        let parsed = raw.and_then(mime::parse);
        let id = s.insert_message(&item.new_message(
            folder_id,
            raw.map_or(0, <[u8]>::len),
            parsed.as_ref(),
        ))?;
        if let Some(p) = &parsed {
            let stored = s.message(id)?.map(|m| m.attachments).unwrap_or_default();
            for (a, data) in stored.iter().zip(&p.attachment_data) {
                s.put_attachment_data(a.id, data)?;
            }
        }
        sum.added += 1;
    }
    Ok(sum)
}
