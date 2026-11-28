use base64::{engine::general_purpose::STANDARD, Engine};
use lazymail_accounts::TokenSource;
use lazymail_store::{Flags, Message, Store};
use reqwest::header::CONTENT_TYPE;
use serde::Deserialize;
use serde_json::json;

use crate::client::{Error, Graph, Result};

/// Graph refuses request bodies over about 4 MB; this is the base64 text's share of it.
const MAX_SEND: usize = 4_000_000;

fn message(store: &Store, id: i64) -> Result<(Message, String)> {
    let m = store.message(id)?.ok_or(Error::NotFound)?;
    let graph_id = m.graph_id.clone().ok_or(Error::NotFound)?;
    Ok((m, graph_id))
}

impl<T: TokenSource> Graph<T> {
    /// Sets read and flagged on the server, then in the store.
    pub async fn set_flags(&self, store: &Store, message_id: i64, flags: Flags) -> Result<()> {
        let (_, graph_id) = message(store, message_id)?;
        let url = self.url(&["me", "messages", &graph_id], &[]);
        let body = json!({
            "isRead": flags.seen,
            "flag": { "flagStatus": if flags.flagged { "flagged" } else { "notFlagged" } },
        });
        self.send(|c| c.patch(url.clone()).json(&body)).await?;
        store.set_flags(message_id, flags)?;
        Ok(())
    }

    pub async fn move_message(&self, store: &Store, message_id: i64, folder_id: i64) -> Result<()> {
        #[derive(Deserialize)]
        struct Moved {
            id: String,
        }
        let (_, graph_id) = message(store, message_id)?;
        let dest = store
            .folder(folder_id)?
            .and_then(|f| f.remote_id)
            .ok_or(Error::NotFound)?;
        let url = self.url(&["me", "messages", &graph_id, "move"], &[]);
        let body = json!({ "destinationId": dest });
        let moved: Moved = self
            .send(|c| c.post(url.clone()).json(&body))
            .await?
            .json()
            .await
            .map_err(|e| Error::BadResponse(e.to_string()))?;
        store.atomic(|s| {
            if moved.id != graph_id {
                s.set_ids(message_id, None, Some(&moved.id))?;
            }
            s.move_message(message_id, folder_id, None)
        })?;
        Ok(())
    }

    /// Moves the message to Deleted Items; one already there is deleted for good.
    pub async fn trash(&self, store: &Store, message_id: i64) -> Result<()> {
        let (m, graph_id) = message(store, message_id)?;
        let in_trash = store
            .folder(m.folder_id)?
            .is_some_and(|f| f.role.as_deref() == Some("trash"));
        if !in_trash {
            let trash = store
                .folders()?
                .into_iter()
                .find(|f| f.role.as_deref() == Some("trash"))
                .ok_or(Error::NotFound)?;
            return self.move_message(store, message_id, trash.id).await;
        }
        let url = self.url(&["me", "messages", &graph_id], &[]);
        self.send(|c| c.delete(url.clone())).await?;
        store.delete_message(message_id)?;
        Ok(())
    }

    /// Sends a finished MIME message; Exchange keeps a copy in Sent Items. A message over
    /// about 3 MB fails with `TooLarge`, since there is no upload session path yet.
    pub async fn send_mail(&self, raw: &[u8]) -> Result<()> {
        let url = self.url(&["me", "sendMail"], &[]);
        let body = STANDARD.encode(raw);
        if body.len() > MAX_SEND {
            return Err(Error::TooLarge);
        }
        self.send(|c| {
            c.post(url.clone())
                .header(CONTENT_TYPE, "text/plain")
                .body(body.clone())
        })
        .await?;
        Ok(())
    }
}
