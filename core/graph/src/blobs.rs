use base64::{engine::general_purpose::STANDARD, Engine};
use lazymail_accounts::TokenSource;
use mail_parser::MessageParser;
use serde::Deserialize;
use serde_json::json;

use crate::client::{Error, Graph, Result};

#[derive(Deserialize)]
struct Page {
    value: Vec<Item>,
    #[serde(rename = "@odata.nextLink")]
    next: Option<String>,
}

#[derive(Deserialize)]
struct Item {
    id: String,
}

/// A top-level folder of messages whose text body is a base64 file, like the settings folder.
/// Ids are the messages' immutable Graph ids.
impl<T: TokenSource> Graph<T> {
    /// The id of the folder, made when it does not exist yet.
    pub async fn blob_folder(&self, name: &str) -> Result<String> {
        let filter = format!("displayName eq '{}'", name.replace('\'', "''"));
        let url = self.url(
            &["me", "mailFolders"],
            &[("$filter", &filter), ("$select", "id")],
        );
        let page: Page = self.get_json(url).await?;
        if let Some(f) = page.value.into_iter().next() {
            return Ok(f.id);
        }
        let url = self.url(&["me", "mailFolders"], &[]);
        let body = json!({ "displayName": name });
        let made: Item = self
            .send(|c| c.post(url.clone()).json(&body))
            .await?
            .json()
            .await
            .map_err(|e| Error::BadResponse(e.to_string()))?;
        Ok(made.id)
    }

    /// Every message of the folder, oldest first.
    pub async fn list_blobs(&self, folder: &str) -> Result<Vec<String>> {
        let mut url = self.url(
            &["me", "mailFolders", folder, "messages"],
            &[("$select", "id"), ("$orderby", "createdDateTime")],
        );
        let mut ids = Vec::new();
        loop {
            let page: Page = self.get_json(url).await?;
            ids.extend(page.value.into_iter().map(|i| i.id));
            match page.next {
                Some(next) => url = self.link(&next)?,
                None => return Ok(ids),
            }
        }
    }

    /// `None` when another device removed the message.
    pub async fn fetch_blob(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let url = self.url(&["me", "messages", id, "$value"], &[]);
        let resp = match self.send(|c| c.get(url.clone())).await {
            Ok(r) => r,
            Err(Error::NotFound) => return Ok(None),
            Err(e) => return Err(e),
        };
        let raw = resp.bytes().await?;
        let text = MessageParser::default()
            .parse(raw.as_ref())
            .and_then(|m| m.body_text(0).map(|t| t.into_owned()))
            .ok_or_else(|| Error::BadResponse("the message has no text".into()))?;
        let packed: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        STANDARD
            .decode(packed)
            .map(Some)
            .map_err(|_| Error::BadResponse("the text is not base64".into()))
    }

    pub async fn append_blob(&self, folder: &str, subject: &str, data: &[u8]) -> Result<String> {
        let url = self.url(&["me", "mailFolders", folder, "messages"], &[]);
        let body = json!({
            "subject": subject,
            "body": { "contentType": "text", "content": STANDARD.encode(data) },
            "isRead": true,
        });
        let made: Item = self
            .send(|c| c.post(url.clone()).json(&body))
            .await?
            .json()
            .await
            .map_err(|e| Error::BadResponse(e.to_string()))?;
        Ok(made.id)
    }

    /// Removing a message that is already gone is not an error.
    pub async fn delete_blob(&self, id: &str) -> Result<()> {
        let url = self.url(&["me", "messages", id], &[]);
        match self.send(|c| c.delete(url.clone())).await {
            Ok(_) | Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }
}
