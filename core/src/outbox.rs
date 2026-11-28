use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use lazymail_accounts::{AuthFailure, MailAccess};
use lazymail_imap::Imap;
use lazymail_smtp::{build, Address, Attachment, Auth, Draft, Outbox, SentBox};
use lazymail_store::{Flags, OutboxState, Store};

use crate::callbacks::Tokens;
use crate::error::{invalid, not_found, Result};
use crate::shared::{AccountRt, Shared};
use crate::types::{MailAddress, OutboxEntry, OutboxReport, OutgoingMessage};

const FIRST_RETRY: i64 = 60;
const LONGEST_RETRY: i64 = 6 * 3600;
const GIVE_UP_AFTER: i64 = 3 * 24 * 3600;

fn address(a: &MailAddress) -> Address {
    match &a.name {
        Some(n) => Address::named(n, &a.email),
        None => Address::new(&a.email),
    }
}

/// The account's Sent folder, found in the store by its role.
struct ImapSentBox {
    imap: Arc<Imap<Tokens>>,
    store: Arc<Mutex<Store>>,
}

impl ImapSentBox {
    fn folder(&self) -> std::result::Result<String, String> {
        let folders = self
            .store
            .lock()
            .unwrap()
            .folders()
            .map_err(|e| e.to_string())?;
        folders
            .into_iter()
            .find(|f| f.role.as_deref() == Some("sent"))
            .map(|f| f.name)
            .ok_or_else(|| "the Sent folder is not known yet".to_string())
    }
}

impl SentBox for ImapSentBox {
    async fn contains(&self, message_id: &str) -> std::result::Result<bool, String> {
        let folder = self.folder()?;
        let mut conn = self.imap.connect().await.map_err(|e| e.to_string())?;
        let found = conn.find_by_message_id(&folder, message_id).await;
        conn.logout().await;
        found.map(|u| !u.is_empty()).map_err(|e| e.to_string())
    }

    async fn append(&self, raw: &[u8]) -> std::result::Result<(), String> {
        let folder = self.folder()?;
        let mut conn = self.imap.connect().await.map_err(|e| e.to_string())?;
        let seen = Flags {
            seen: true,
            ..Flags::default()
        };
        let done = conn.append_message(&folder, raw, seen).await;
        conn.logout().await;
        done.map(drop).map_err(|e| e.to_string())
    }
}

fn backoff(attempts: u32) -> i64 {
    (FIRST_RETRY << attempts.min(10)).min(LONGEST_RETRY)
}

impl Shared {
    /// Puts a message in the account's Outbox. It goes out on the next run of the Outbox.
    pub(crate) fn queue(&self, account_id: &str, m: OutgoingMessage) -> Result<OutboxEntry> {
        let acc = self.account(account_id)?;
        let own = {
            let a = acc.account.lock().unwrap();
            let id = &a.identities[0];
            Address::named(&id.name, &id.address)
        };
        let draft = Draft {
            from: Some(m.from.as_ref().map_or(own, address)),
            to: m.to.iter().map(address).collect(),
            cc: m.cc.iter().map(address).collect(),
            bcc: m.bcc.iter().map(address).collect(),
            subject: m.subject,
            text: m.text,
            html: m.html,
            attachments: m
                .attachments
                .into_iter()
                .map(|f| Attachment {
                    filename: f.filename,
                    content_type: f.content_type,
                    data: f.data,
                })
                .collect(),
            in_reply_to: m.in_reply_to,
            references: m.references,
            date: self.now(),
            ..Draft::default()
        };
        let built = build(&draft)?;
        let store = acc.store.lock().unwrap();
        let id = store.outbox_enqueue(&built.message_id, &built.raw, self.now())?;
        let item = store
            .outbox_item(id)?
            .ok_or_else(|| not_found("outbox row"))?;
        drop(store);
        acc.wake.notify_one();
        Ok(item.into())
    }

    pub(crate) fn outbox(&self, account_id: &str) -> Result<Vec<OutboxEntry>> {
        let acc = self.account(account_id)?;
        let items = acc.store.lock().unwrap().outbox_list()?;
        Ok(items.into_iter().map(Into::into).collect())
    }

    /// Queues a failed or waiting item again, to go out now.
    pub(crate) fn outbox_retry(&self, account_id: &str, id: i64) -> Result<()> {
        let acc = self.account(account_id)?;
        acc.store.lock().unwrap().outbox_requeue(id, self.now())?;
        acc.wake.notify_one();
        Ok(())
    }

    pub(crate) fn outbox_remove(&self, account_id: &str, id: i64) -> Result<()> {
        let acc = self.account(account_id)?;
        let store = acc.store.lock().unwrap();
        match store.outbox_item(id)? {
            Some(i) if i.state == OutboxState::Sending => {
                Err(invalid("this message is being sent"))
            }
            Some(_) => Ok(store.outbox_remove(id)?),
            None => Err(not_found("outbox row")),
        }
    }

    /// Deals with mail a crash left in Sending. Call it once when the core starts.
    pub(crate) fn recover_outbox(&self, acc: &AccountRt) -> Result<()> {
        let store = self.open_store(acc)?;
        let account = acc.account.lock().unwrap().clone();
        match account.mail {
            MailAccess::Imap => {
                let sent_box = NoSentBox;
                let outbox = Outbox {
                    store: &store,
                    tokens: &self.tokens,
                    sent_box: &sent_box,
                    auth: Auth::OAuth,
                    pinned_cert: None,
                };
                outbox.recover(&account, self.now())?;
            }
            // Exchange files the copy itself, but nothing shows whether it took a request
            // that was cut off, so the person decides.
            MailAccess::Graph => {
                for item in store.outbox_list()? {
                    if item.state == OutboxState::Sending {
                        let note = "may already have been sent: the app stopped while sending it";
                        store.outbox_fail(item.id, note, None, true)?;
                    }
                }
            }
            MailAccess::None => {}
        }
        Ok(())
    }

    /// Sends what is due and files the Sent copies.
    pub(crate) async fn run_outbox(&self, acc: &AccountRt) -> Result<OutboxReport> {
        let report = match acc.mode() {
            MailAccess::Imap => self.run_imap_outbox(acc).await?,
            MailAccess::Graph => self.run_graph_outbox(acc).await?,
            MailAccess::None => OutboxReport::default(),
        };
        self.emit_outbox(acc, report);
        Ok(report)
    }

    async fn run_imap_outbox(&self, acc: &AccountRt) -> Result<OutboxReport> {
        let Some(imap) = acc.imap() else {
            return Ok(OutboxReport::default());
        };
        let mut account = acc.account.lock().unwrap().clone();
        let auth = if account.provider.uses_microsoft_sign_in() {
            Auth::OAuth
        } else if let Some(p) = acc.password() {
            Auth::Password(p)
        } else {
            self.report_failure(acc, AuthFailure::AppPasswordRequired);
            return Ok(OutboxReport::default());
        };
        let mut signin = acc.signin.lock().unwrap().clone();
        let before = serde_json::to_string(&signin).expect("plain data");
        let store = self.open_store(acc)?;
        let sent_box = ImapSentBox {
            imap,
            store: acc.store.clone(),
        };
        let outbox = Outbox {
            store: &store,
            tokens: &self.tokens,
            sent_box: &sent_box,
            auth,
            pinned_cert: acc.pinned.clone(),
        };
        let report = outbox.run(&mut account, &mut signin, self.now()).await?;
        if serde_json::to_string(&signin).expect("plain data") != before {
            *acc.signin.lock().unwrap() = signin;
            acc.account.lock().unwrap().mail = account.mail;
            let _ = acc.save();
        }
        for e in report.events {
            self.sign_in_event(acc, e);
        }
        Ok(OutboxReport {
            sent: report.sent as u32,
            retry: report.retry as u32,
            failed: report.failed as u32,
            copies_pending: report.copies_pending as u32,
        })
    }

    /// Exchange files the Sent copy itself. TODO: no search of Sent for an unsure send, so a
    /// retry after a lost reply can send twice.
    async fn run_graph_outbox(&self, acc: &AccountRt) -> Result<OutboxReport> {
        let store = self.open_store(acc)?;
        let now = self.now();
        let mut report = OutboxReport::default();
        let paused = {
            let mut s = acc.signin.lock().unwrap();
            s.work_paused(&acc.id) && !s.try_retry(&acc.id, SystemTime::now())
        };
        if paused {
            return Ok(report);
        }
        for item in store.outbox_due(now)? {
            if store.outbox_begin_send(item.id, now).is_err() {
                continue;
            }
            match self.graph_call(acc, acc.graph.send_mail(&item.raw)).await {
                Ok(()) => {
                    store.outbox_mark_sent(item.id, now)?;
                    store.outbox_remove(item.id)?;
                    report.sent += 1;
                }
                Err(crate::error::CoreError::SignIn { detail }) => {
                    store.outbox_fail(item.id, &detail, Some(now), false)?;
                    report.retry += 1;
                    break;
                }
                Err(e) => {
                    let first = item.first_try.unwrap_or(now);
                    let text = e.to_string();
                    let permanent = matches!(&e, crate::error::CoreError::Unsupported { .. })
                        || text.contains("message too large")
                        || now - first >= GIVE_UP_AFTER;
                    if permanent {
                        store.outbox_fail(item.id, &text, None, false)?;
                        report.failed += 1;
                    } else {
                        store.outbox_fail(
                            item.id,
                            &text,
                            Some(now + backoff(item.attempts)),
                            false,
                        )?;
                        report.retry += 1;
                    }
                }
            }
        }
        Ok(report)
    }
}

/// Stands in where `Outbox::recover` needs a Sent folder it never reads.
struct NoSentBox;

impl SentBox for NoSentBox {
    async fn contains(&self, _: &str) -> std::result::Result<bool, String> {
        Err("no Sent folder".into())
    }

    async fn append(&self, _: &[u8]) -> std::result::Result<(), String> {
        Err("no Sent folder".into())
    }
}
