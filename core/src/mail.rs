use lazymail_accounts::{AuthFailure, MailAccess};
use lazymail_store::{Message, SearchQuery};

use crate::error::{invalid, not_found, CoreError, Result};
use crate::shared::{AccountRt, Shared};
use crate::types::{
    AttachmentInfo, FlagSet, FolderInfo, MessageDetail, MessageSummary, SearchRequest, SyncSummary,
};

fn summary(m: &Message) -> MessageSummary {
    MessageSummary {
        id: m.id,
        folder_id: m.folder_id,
        thread_id: m.thread_id,
        subject: m.subject.clone(),
        from_name: m.from_name.clone(),
        from_addr: m.from_addr.clone(),
        date: m.date,
        flags: m.flags.into(),
        has_attachments: m.has_attachments,
        snippet: m.preview.clone(),
    }
}

fn query(r: &SearchRequest) -> SearchQuery {
    SearchQuery {
        text: r.text.clone(),
        from: r.from.clone(),
        to: r.to.clone(),
        subject: r.subject.clone(),
        folder_id: r.folder_id,
        label: r.label.clone(),
        after: r.after,
        before: r.before,
        has_attachment: r.has_attachment,
        unread: r.unread,
        flagged: r.flagged,
        limit: r.limit as usize,
        offset: r.offset as usize,
    }
}

impl Shared {
    pub(crate) fn folders(&self, account_id: &str) -> Result<Vec<FolderInfo>> {
        let acc = self.account(account_id)?;
        let folders = acc.store.lock().unwrap().folders()?;
        Ok(folders
            .into_iter()
            .map(|f| FolderInfo {
                id: f.id,
                name: f.name,
                role: f.role,
            })
            .collect())
    }

    /// The folder's messages, newest first.
    pub(crate) fn messages(
        &self,
        account_id: &str,
        folder_id: i64,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<MessageSummary>> {
        self.search(
            account_id,
            &SearchRequest {
                folder_id: Some(folder_id),
                limit,
                offset,
                ..SearchRequest::default()
            },
        )
    }

    pub(crate) fn search(
        &self,
        account_id: &str,
        r: &SearchRequest,
    ) -> Result<Vec<MessageSummary>> {
        let acc = self.account(account_id)?;
        let hits = acc.store.lock().unwrap().search(&query(r))?;
        Ok(hits.into_iter().map(Into::into).collect())
    }

    pub(crate) fn message(&self, account_id: &str, message_id: i64) -> Result<MessageDetail> {
        let acc = self.account(account_id)?;
        let m = acc
            .store
            .lock()
            .unwrap()
            .message(message_id)?
            .ok_or_else(|| not_found("message"))?;
        Ok(MessageDetail {
            summary: summary(&m),
            to: m.to,
            cc: m.cc,
            message_id: m.message_id,
            in_reply_to: m.in_reply_to,
            references: m.references,
            labels: m.labels,
            body_text: m.body_text,
            body_html: m.body_html,
            attachments: m
                .attachments
                .into_iter()
                .map(|a| AttachmentInfo {
                    id: a.id,
                    filename: a.filename,
                    mime: a.mime,
                    size: a.size,
                    content_id: a.content_id,
                    stored: a.stored,
                })
                .collect(),
        })
    }

    pub(crate) async fn attachment(
        &self,
        account_id: &str,
        message_id: i64,
        attachment_id: i64,
    ) -> Result<Vec<u8>> {
        let acc = self.account(account_id)?;
        if let Some(d) = acc.store.lock().unwrap().attachment_data(attachment_id)? {
            return Ok(d);
        }
        match acc.mode() {
            MailAccess::Imap => {
                let imap = acc.imap().ok_or_else(|| invalid("no mail server"))?;
                let mut conn = imap.connect().await?;
                let data = conn
                    .download_attachment(&acc.store, message_id, attachment_id)
                    .await;
                conn.logout().await;
                Ok(data?)
            }
            _ => Err(CoreError::Unsupported {
                detail: "this account's attachments are downloaded with its mail".into(),
            }),
        }
    }

    pub(crate) async fn set_flags(
        &self,
        account_id: &str,
        message_id: i64,
        flags: FlagSet,
    ) -> Result<()> {
        let acc = self.account(account_id)?;
        match acc.mode() {
            MailAccess::Imap => {
                let imap = acc.imap().ok_or_else(|| invalid("no mail server"))?;
                let mut conn = imap.connect().await?;
                let done = conn.set_flags(&acc.store, message_id, flags.into()).await;
                conn.logout().await;
                Ok(done?)
            }
            MailAccess::Graph => {
                let store = self.open_store(&acc)?;
                self.graph_call(&acc, acc.graph.set_flags(&store, message_id, flags.into()))
                    .await
            }
            MailAccess::None => Ok(acc
                .store
                .lock()
                .unwrap()
                .set_flags(message_id, flags.into())?),
        }
    }

    pub(crate) async fn move_message(
        &self,
        account_id: &str,
        message_id: i64,
        folder_id: i64,
    ) -> Result<()> {
        let acc = self.account(account_id)?;
        match acc.mode() {
            MailAccess::Imap => {
                let imap = acc.imap().ok_or_else(|| invalid("no mail server"))?;
                let mut conn = imap.connect().await?;
                let done = conn
                    .move_message(&acc.store, message_id, folder_id, self.now())
                    .await;
                conn.logout().await;
                done?;
                Ok(())
            }
            MailAccess::Graph => {
                let store = self.open_store(&acc)?;
                self.graph_call(&acc, acc.graph.move_message(&store, message_id, folder_id))
                    .await
            }
            MailAccess::None => Ok(acc
                .store
                .lock()
                .unwrap()
                .move_message(message_id, folder_id, None)?),
        }
    }

    /// Deletes a message for good over IMAP; over Graph it goes to Deleted Items first.
    pub(crate) async fn delete_message(&self, account_id: &str, message_id: i64) -> Result<()> {
        let acc = self.account(account_id)?;
        match acc.mode() {
            MailAccess::Imap => {
                let imap = acc.imap().ok_or_else(|| invalid("no mail server"))?;
                let mut conn = imap.connect().await?;
                let done = conn.delete_message(&acc.store, message_id).await;
                conn.logout().await;
                Ok(done?)
            }
            MailAccess::Graph => {
                let store = self.open_store(&acc)?;
                self.graph_call(&acc, acc.graph.trash(&store, message_id))
                    .await
            }
            MailAccess::None => Ok(acc.store.lock().unwrap().delete_message(message_id)?),
        }
    }

    /// Runs a Graph call and turns a refused token into the account's "needs sign-in" state.
    pub(crate) async fn graph_call<T>(
        &self,
        acc: &AccountRt,
        call: impl std::future::Future<Output = lazymail_graph::Result<T>>,
    ) -> Result<T> {
        match call.await {
            Ok(v) => {
                acc.signin.lock().unwrap().report_success(&acc.id);
                Ok(v)
            }
            Err(e) => {
                if matches!(e, lazymail_graph::Error::NeedsSignIn) {
                    self.report_failure(acc, AuthFailure::SignInExpired);
                }
                Err(e.into())
            }
        }
    }

    /// One pass over the account: its mail, then its Outbox. Returns what the mail pass changed.
    pub(crate) async fn sync_account(&self, account_id: &str) -> Result<SyncSummary> {
        let acc = self.account(account_id)?;
        let summary = match acc.mode() {
            MailAccess::Imap => {
                let imap = acc.imap().ok_or_else(|| invalid("no mail server"))?;
                let s = imap.sync().await;
                let _ = acc.save();
                let s = s?;
                SyncSummary {
                    added: s.added,
                    removed: s.removed,
                    changed: s.changed,
                }
            }
            MailAccess::Graph => self.sync_graph(&acc).await?,
            MailAccess::None => SyncSummary::default(),
        };
        self.run_outbox(&acc).await?;
        Ok(summary)
    }

    pub(crate) async fn sync_graph(&self, acc: &AccountRt) -> Result<SyncSummary> {
        let store = self.open_store(acc)?;
        let report = self.graph_call(acc, acc.graph.sync(&store)).await?;
        let _ = acc.save();
        for (folder_id, failure) in &report.failed {
            let name = store
                .folder(*folder_id)
                .ok()
                .flatten()
                .map_or_else(String::new, |f| f.name);
            self.events.emit(crate::types::CoreEvent::FolderFailed {
                account_id: acc.id.clone(),
                folder: name,
                reason: failure.to_string(),
            });
        }
        Ok(SyncSummary {
            added: report.summary.added as u32,
            removed: report.summary.removed as u32,
            changed: report.summary.updated as u32,
        })
    }
}
