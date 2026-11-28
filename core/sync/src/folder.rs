use std::sync::{Arc, Mutex};

use crate::Result;

/// The "Alazy" folder of one account. Ids are opaque and `list` returns
/// them in the order the messages were added.
// Only used through generics, so the auto-trait bounds of the futures do not matter yet.
#[allow(async_fn_in_trait)]
pub trait Folder {
    /// Names the folder, for example by a hash of the account address.
    /// Messages are sealed for one scope and do not open in another, so a
    /// message copied into another account's folder is ignored.
    fn scope(&self) -> &str;
    async fn list(&self) -> Result<Vec<String>>;
    /// `None` when another device removed the message in the meantime.
    async fn fetch(&self, id: &str) -> Result<Option<Vec<u8>>>;
    async fn append(&self, body: Vec<u8>) -> Result<String>;
    /// Removing a message that is already gone is not an error.
    async fn delete(&self, id: &str) -> Result<()>;
}

/// Clones share the same messages, like several devices sharing one mailbox.
#[derive(Clone, Default)]
pub struct MemoryFolder(Arc<Mutex<Inner>>, Arc<str>);

#[derive(Default)]
struct Inner {
    next: u64,
    messages: Vec<(String, Vec<u8>)>,
}

impl MemoryFolder {
    pub fn new() -> Self {
        Self::default()
    }

    /// A folder with its own scope, as every account's folder has.
    pub fn with_scope(scope: &str) -> Self {
        MemoryFolder(Arc::default(), scope.into())
    }

    /// The raw stored bodies, for tests that check nothing readable is kept.
    pub fn bodies(&self) -> Vec<Vec<u8>> {
        let inner = self.0.lock().unwrap();
        inner.messages.iter().map(|(_, b)| b.clone()).collect()
    }
}

impl Folder for MemoryFolder {
    fn scope(&self) -> &str {
        &self.1
    }

    async fn list(&self) -> Result<Vec<String>> {
        let inner = self.0.lock().unwrap();
        Ok(inner.messages.iter().map(|(id, _)| id.clone()).collect())
    }

    async fn fetch(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let inner = self.0.lock().unwrap();
        Ok(inner
            .messages
            .iter()
            .find(|(i, _)| i == id)
            .map(|(_, b)| b.clone()))
    }

    async fn append(&self, body: Vec<u8>) -> Result<String> {
        let mut inner = self.0.lock().unwrap();
        inner.next += 1;
        let id = inner.next.to_string();
        inner.messages.push((id.clone(), body));
        Ok(id)
    }

    async fn delete(&self, id: &str) -> Result<()> {
        self.0.lock().unwrap().messages.retain(|(i, _)| i != id);
        Ok(())
    }
}
