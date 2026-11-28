use std::future::Future;
use std::time::{Duration, SystemTime};

use lazymail_accounts::{Account, Event, MailAccess, SignIn, TokenSource};
use lazymail_store::{OutboxItem, OutboxState, Store};

use crate::transport::{Auth, SendError, Smtp};
use crate::Result;

const FIRST_RETRY: i64 = 60;
const LONGEST_RETRY: i64 = 6 * 3600;
const GIVE_UP_AFTER: i64 = 3 * 24 * 3600;
/// How long a server gets to file a Sent copy itself before one is appended.
const COPY_WAIT: i64 = 30;

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
    /// Mail that will never go out, or may already have gone out, and waits for the person.
    pub failed: usize,
    /// Sent mail whose copy is not in the Sent folder yet; it is looked at again on the next run.
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
    /// Deals with mail a crash left in Sending. Call it once when the app starts, before the
    /// first run: during a run a Sending row is a live send, and putting it back in the queue
    /// would send it twice. Where the provider files Sent mail itself the mail goes back in the
    /// queue and Sent is searched first. Elsewhere nothing shows whether the server took it,
    /// so it is parked for the person to decide.
    pub fn recover(&self, account: &Account, now: i64) -> Result<()> {
        if !files_sent(account) {
            for item in self.store.outbox_list()? {
                if item.state == OutboxState::Sending {
                    let note = "may already have been sent: the app stopped while sending it";
                    self.store.outbox_fail(item.id, note, None, true)?;
                }
            }
        }
        self.store.outbox_requeue_interrupted(now)?;
        Ok(())
    }

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
        let files_sent = files_sent(account);
        self.file_copies(files_sent, now, &mut report).await?;

        let due = self.store.outbox_due(now)?;
        if due.is_empty() {
            return Ok(report);
        }
        let mut smtp = match Smtp::new(
            account,
            &self.auth,
            self.tokens,
            self.pinned_cert.as_deref(),
        )
        .await
        {
            Ok(s) => s,
            Err(SendError::Auth(f)) => {
                report.events.extend(signin.report_failure(account, f, at));
                return Ok(report);
            }
            Err(e) => {
                for item in due {
                    if self.begin(&item, now)? {
                        self.settle(&item, e.clone(), now, files_sent, &mut report)?;
                    }
                }
                return Ok(report);
            }
        };

        // Once the server cannot be reached the rest of the queue gets the same answer
        // without another connection attempt each.
        let mut offline: Option<SendError> = None;
        for item in due {
            if !self.begin(&item, now)? {
                continue;
            }
            if let Some(e) = &offline {
                self.settle(&item, e.clone(), now, files_sent, &mut report)?;
                continue;
            }
            if item.check_sent {
                match self.sent_box.contains(&item.message_id).await {
                    Ok(true) => {
                        self.store.outbox_mark_sent(item.id, now)?;
                        self.store.outbox_remove(item.id)?;
                        report.sent += 1;
                        continue;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        let msg = format!("could not search Sent: {e}");
                        self.retry_later(&item, &msg, now, false, &mut report)?;
                        continue;
                    }
                }
            }
            match smtp.send(&item.raw).await {
                Ok(()) => {
                    signin.report_success(&account.id);
                    self.store.outbox_mark_sent(item.id, now + COPY_WAIT)?;
                    if files_sent {
                        self.store.outbox_remove(item.id)?;
                    }
                    report.sent += 1;
                }
                Err(SendError::Auth(f)) => {
                    // The mail is untouched and goes out when the account signs in again.
                    self.store
                        .outbox_fail(item.id, f.message(), Some(now), false)?;
                    report.retry += 1;
                    report.events.extend(signin.report_failure(account, f, at));
                    break;
                }
                Err(e) => {
                    if let SendError::Offline(_) = e {
                        offline = Some(e.clone());
                    }
                    self.settle(&item, e, now, files_sent, &mut report)?;
                }
            }
        }
        smtp.close().await;
        Ok(report)
    }

    /// Starts sending a due item. False when it is gone or another run has it.
    fn begin(&self, item: &OutboxItem, now: i64) -> Result<bool> {
        match self.store.outbox_begin_send(item.id, now) {
            Ok(()) => Ok(true),
            Err(lazymail_store::Error::NotFound) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Records a failed attempt on an item in Sending.
    fn settle(
        &self,
        item: &OutboxItem,
        err: SendError,
        now: i64,
        files_sent: bool,
        report: &mut Report,
    ) -> Result<()> {
        match err {
            SendError::Temporary(e) | SendError::Offline(e) => {
                self.retry_later(item, &e, now, false, report)
            }
            // Where the provider files Sent mail, the next try looks there first. Elsewhere
            // nothing could show it, and a second copy is worse than a late one.
            SendError::Unsure(e) if files_sent => self.retry_later(item, &e, now, true, report),
            SendError::Unsure(e) => {
                let msg = format!("may already have been sent: {e}");
                self.store.outbox_fail(item.id, &msg, None, true)?;
                report.failed += 1;
                Ok(())
            }
            SendError::Permanent(e) => {
                self.store.outbox_fail(item.id, &e, None, false)?;
                report.failed += 1;
                Ok(())
            }
            SendError::Auth(f) => {
                self.store
                    .outbox_fail(item.id, f.message(), Some(now), false)?;
                report.retry += 1;
                Ok(())
            }
        }
    }

    /// Queues the item again with a growing delay, or gives up three days after its first
    /// attempt.
    fn retry_later(
        &self,
        item: &OutboxItem,
        error: &str,
        now: i64,
        unsure: bool,
        report: &mut Report,
    ) -> Result<()> {
        if now - item.first_try.unwrap_or(now) < GIVE_UP_AFTER {
            let next = now + backoff(item.attempts);
            self.store.outbox_fail(item.id, error, Some(next), unsure)?;
            report.retry += 1;
        } else {
            let msg = format!("gave up after three days: {error}");
            self.store.outbox_fail(item.id, &msg, None, unsure)?;
            report.failed += 1;
        }
        Ok(())
    }

    /// Mail the server took stays in the Outbox as Sent until its copy is in the Sent folder,
    /// unless the provider files it itself. Other servers get COPY_WAIT seconds to do it; the
    /// folder is searched before appending, which also makes an append whose reply was lost
    /// safe to try again.
    async fn file_copies(&self, files_sent: bool, now: i64, report: &mut Report) -> Result<()> {
        for item in self.store.outbox_list()? {
            if item.state != OutboxState::Sent {
                continue;
            }
            if files_sent {
                self.store.outbox_remove(item.id)?;
            } else if now < item.next_try {
                report.copies_pending += 1;
            } else {
                let filed = match self.sent_box.contains(&item.message_id).await {
                    Ok(true) => true,
                    Ok(false) => self.sent_box.append(&item.raw).await.is_ok(),
                    Err(_) => false,
                };
                if filed {
                    self.store.outbox_remove(item.id)?;
                } else {
                    report.copies_pending += 1;
                }
            }
        }
        Ok(())
    }
}

fn files_sent(account: &Account) -> bool {
    account.settings.as_ref().is_some_and(|s| s.files_sent)
}

fn backoff(attempts: u32) -> i64 {
    (FIRST_RETRY << attempts.min(10)).min(LONGEST_RETRY)
}
