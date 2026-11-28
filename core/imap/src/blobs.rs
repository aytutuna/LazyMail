use crate::conn::{quote, Connection};
use crate::error::{Error, Result};
use crate::sync::fetch_part;
use crate::utf7;
use lazymail_store::Flags;

/// A message in a private folder, named by the folder's UIDVALIDITY and its UID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobRef {
    pub validity: u32,
    pub uid: u32,
}

/// A folder of one-part messages whose body is a binary file, like the settings folder. The
/// folder is made when it is first asked for.
impl Connection {
    async fn open_blobs(&mut self, folder: &str) -> Result<u32> {
        match self.select(folder).await {
            Ok(s) => Ok(s.validity),
            Err(Error::Refused(_)) => {
                self.exec(&format!("CREATE {}", quote(&utf7::encode(folder))?))
                    .await?;
                Ok(self.select(folder).await?.validity)
            }
            Err(e) => Err(e),
        }
    }

    /// Every message of the folder, oldest first.
    pub async fn list_blobs(&mut self, folder: &str) -> Result<Vec<BlobRef>> {
        let validity = self.open_blobs(folder).await?;
        let uids = self.uid_search("ALL").await?;
        Ok(uids
            .into_iter()
            .map(|uid| BlobRef { validity, uid })
            .collect())
    }

    /// `None` when the message is gone or the folder was made again since the reference was taken.
    pub async fn fetch_blob(&mut self, folder: &str, at: BlobRef) -> Result<Option<Vec<u8>>> {
        let validity = self.open_blobs(folder).await?;
        if validity != at.validity
            || self
                .uid_search(&format!("UID {}", at.uid))
                .await?
                .is_empty()
        {
            return Ok(None);
        }
        Ok(Some(fetch_part(self, folder, at.uid, "1").await?))
    }

    /// Adds a finished message and returns where it landed. `message_id` is the message's own
    /// Message-ID, used to find it when the server does not report the new UID.
    pub async fn append_blob(
        &mut self,
        folder: &str,
        raw: &[u8],
        message_id: &str,
    ) -> Result<BlobRef> {
        let validity = self.open_blobs(folder).await?;
        let flags = Flags {
            seen: true,
            ..Flags::default()
        };
        if let Some(p) = self.append_message(folder, raw, flags).await? {
            return Ok(BlobRef {
                validity: p.uidvalidity,
                uid: p.uid,
            });
        }
        let found = self.find_by_message_id(folder, message_id).await?;
        match found.last() {
            Some(&uid) => Ok(BlobRef { validity, uid }),
            None => Err(Error::Protocol("the appended message is not there".into())),
        }
    }

    /// Removing a message that is already gone is not an error.
    pub async fn delete_blob(&mut self, folder: &str, at: BlobRef) -> Result<()> {
        let validity = self.open_blobs(folder).await?;
        if validity != at.validity
            || self
                .uid_search(&format!("UID {}", at.uid))
                .await?
                .is_empty()
        {
            return Ok(());
        }
        self.check_expungeable(at.uid).await?;
        self.expunge(at.uid).await
    }
}
