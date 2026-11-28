use std::future::Future;
use std::time::{Duration, SystemTime};

use lazymail_accounts::{Account, Event, MailAccess, SignIn, TokenSource};
use lazymail_store::{OutboxItem, OutboxState, Store};

use crate::transport::{Auth, SendError, Smtp};
use crate::Result;

const FIRST_RETRY: i64 = 60;
const LONGEST_RETRY: i64 = 6 * 3600;
const GIVE_UP_AFTER: i64 = 3 * 24 * 3600;

/// The account's Sent folder over IMAP.
pub trait SentBox {
    /// Whether a message with this Message-ID (with angle brackets) is in Sent.
    fn contains(&self, message_id: &str)
        -> impl Future<Output = std::result::Result<bool, String>>;
    fn append(&self, raw: &[u8]) -> impl Future<Output = std::result::Result<(), String>>;
}

#[derive(Debug, Default)]
pub struct Report {
    /// Mail the server took, or that Sent showed was already out.
    pub sent: usize,
    /// Mail that failed for now and waits for its next try.
    pub retry: usize,
    /// Mail that will never go out and waits for the person.
    pub failed: usize,
    /// Sent mail whose copy could not be filed yet; it is tried again on the next run.
    pub copies_pending: usize,
    pub events: Vec<Event>,
}

pub struct Outbox<'a, T, S> {
    pub store: &'a Store,
    pub tokens: &'a T,
    pub sent_box: &'a S,
    pub auth: Auth,
    pub pinned_cert: Option<Vec<u8>>,
}

impl<T: TokenSource, S: SentBox> Outbox<'_, T, S> {
    /// Sends what is due and files the Sent copies. An account that needs sign-in is left alone
    /// except for one attempt an hour; other accounts have their own Outbox.
    pub async fn run(
        &self,
        account: &mut Account,
        signin: &mut SignIn,
        now: i64,
    ) -> Result<Report> {
        let mut report = Report::default();
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(now.max(0) as u64);
        if account.mail != MailAccess::Imap
            || (signin.work_paused(&account.id) && !signin.try_retry(&account.id, at))
        {
            return Ok(report);
        }
        self.store.outbox_requeue_interrupted(now)?;
        self.file_copies(account, &mut report).await?;

        let due = self.store.outbox_due(now)?;
        if due.is_empty() {
            return Ok(report);
        }
        let smtp = match Smtp::new(
            account,
            &self.auth,
            self.tokens,
            self.pinned_cert.as_deref(),
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                if let SendError::Auth(f) = e {
                    report.events.extend(signin.report_failure(account, f, at));
                }
                return Ok(report);
            }
        };

        for item in due {
            self.store.outbox_begin_send(item.id)?;
            match self.in_sent(&item).await {
                Lookup::Found => {
                    self.store.outbox_mark_sent(item.id)?;
                    self.store.outbox_remove(item.id)?;
                    report.sent += 1;
                    continue;
                }
                Lookup::Unknown(e) => {
                    let msg = format!("could not search Sent: {e}");
                    self.store
                        .outbox_fail(item.id, &msg, Some(now + backoff(item.attempts)))?;
                    report.retry += 1;
                    continue;
                }
                Lookup::Missing => {}
            }
            match smtp.send(&item.raw).await {
                Ok(()) => {
                    signin.report_success(&account.id);
                    self.store.outbox_mark_sent(item.id)?;
                    report.sent += 1;
                }
                Err(SendError::Auth(f)) => {
                    // The mail is untouched and goes out when the account signs in again.
                    self.store.outbox_fail(item.id, f.message(), Some(now))?;
                    report.retry += 1;
                    report.events.extend(signin.report_failure(account, f, at));
                    break;
                }
                Err(SendError::Temporary(e)) if now - item.created < GIVE_UP_AFTER => {
                    self.store
                        .outbox_fail(item.id, &e, Some(now + backoff(item.attempts)))?;
                    report.retry += 1;
                }
                Err(SendError::Temporary(e)) => {
                    let msg = format!("gave up after three days: {e}");
                    self.store.outbox_fail(item.id, &msg, None)?;
                    report.failed += 1;
                }
                Err(SendError::Permanent(e)) => {
                    self.store.outbox_fail(item.id, &e, None)?;
                    report.failed += 1;
                }
            }
        }
        self.file_copies(account, &mut report).await?;
        Ok(report)
    }

    /// A retry or scheduled mail may have gone out already with its reply lost, so Sent is
    /// searched for its Message-ID first. If Sent cannot be searched the mail waits, since
    /// sending twice is worse than sending late.
    async fn in_sent(&self, item: &OutboxItem) -> Lookup {
        if item.attempts == 0 && item.next_try == item.created {
            return Lookup::Missing;
        }
        match self.sent_box.contains(&item.message_id).await {
            Ok(true) => Lookup::Found,
            Ok(false) => Lookup::Missing,
            Err(e) => Lookup::Unknown(e),
        }
    }

    /// Mail the server took stays in the Outbox as Sent until its copy is in the Sent folder,
    /// unless the provider files it itself.
    async fn file_copies(&self, account: &Account, report: &mut Report) -> Result<()> {
        let files_sent = account.settings.as_ref().is_some_and(|s| s.files_sent);
        for item in self.store.outbox_list()? {
            if item.state != OutboxState::Sent {
                continue;
            }
            if files_sent || self.sent_box.append(&item.raw).await.is_ok() {
                self.store.outbox_remove(item.id)?;
            } else {
                report.copies_pending += 1;
            }
        }
        Ok(())
    }
}

enum Lookup {
    Found,
    Missing,
    Unknown(String),
}

fn backoff(attempts: u32) -> i64 {
    (FIRST_RETRY << attempts.min(10)).min(LONGEST_RETRY)
}
