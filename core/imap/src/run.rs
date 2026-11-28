use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lazymail_accounts::{
    Account, AuthFailure, Event, Resource, SignIn, TokenError, TokenSource, RETRY_INTERVAL,
};
use lazymail_store::Store;
use rustls::ClientConfig;
use tokio::sync::mpsc::UnboundedSender;

use crate::conn::{Connection, Credential, IdleEnd, Server};
use crate::error::{Error, Result};
use crate::folders;
use crate::stop::Stop;
use crate::sync::{drop_unplaced, sync_folder, Policy, Progress, Summary};

/// A server may drop an IDLE that lasts longer than 29 minutes; a shorter one also finds a
/// connection that went dead without a word (a NAT timeout, a change of network) sooner.
const IDLE_MAX: Duration = Duration::from_secs(10 * 60);
const POLL: Duration = Duration::from_secs(5 * 60);
const PAUSED_CHECK: Duration = Duration::from_secs(60);
const DAY: Duration = Duration::from_secs(24 * 60 * 60);
/// How long an action waits for one of the account's connections before giving up.
const PERMIT_WAIT: Duration = Duration::from_secs(30);

/// What the app should show or act on, sent as it happens.
#[derive(Debug)]
pub enum Update {
    SignIn(Event),
    Progress(Progress),
    Synced {
        folder: String,
        summary: Summary,
    },
    /// Gmail's daily download limit was reached; syncing waits until `resume_at`.
    DownloadLimit {
        resume_at: SystemTime,
    },
    /// One folder could not be synced; the others were.
    FolderFailed {
        folder: String,
        reason: String,
    },
}

/// Waits 1 s after the first failure and doubles up to 5 minutes.
#[derive(Debug, Default)]
struct Backoff {
    failures: u32,
}

impl Backoff {
    fn wait(&mut self) -> Duration {
        let secs = 1u64 << self.failures.min(9);
        self.failures += 1;
        Duration::from_secs(secs.min(300))
    }

    fn reset(&mut self) {
        self.failures = 0;
    }
}

/// One account's IMAP side: sign-in, syncing into the store and keeping up through IDLE.
pub struct Imap<T> {
    pub server: Server,
    account: Arc<Mutex<Account>>,
    password: Option<String>,
    tokens: Arc<T>,
    tls: Arc<ClientConfig>,
    store: Arc<Mutex<Store>>,
    signin: Arc<Mutex<SignIn>>,
    policy: Policy,
    updates: UnboundedSender<Update>,
    verified: AtomicBool,
    // Two connections must not sync the same folder at once.
    sync_lock: tokio::sync::Mutex<()>,
    // Gmail allows three connections per account and device; other providers have their own.
    connections: Arc<tokio::sync::Semaphore>,
    // Folder watchers beyond the first connection; one connection is always left for actions.
    watch_slots: Arc<tokio::sync::Semaphore>,
}

impl<T: TokenSource> Imap<T> {
    /// None when the account has no IMAP server to talk to (local, or reading through Graph).
    pub fn new(
        account: Arc<Mutex<Account>>,
        password: Option<String>,
        tokens: Arc<T>,
        store: Arc<Mutex<Store>>,
        signin: Arc<Mutex<SignIn>>,
        updates: UnboundedSender<Update>,
    ) -> Option<Imap<T>> {
        let (server, limit) = {
            let a = account.lock().unwrap();
            let limit = a.settings.as_ref().map_or(1, |s| s.max_connections.max(1));
            (Server::of(&a)?, limit)
        };
        Some(Imap {
            server,
            account,
            password,
            tokens,
            tls: Arc::new(lazymail_accounts::tls_config()),
            store,
            signin,
            policy: Policy::default(),
            updates,
            verified: AtomicBool::new(false),
            sync_lock: tokio::sync::Mutex::new(()),
            connections: Arc::new(tokio::sync::Semaphore::new(limit as usize)),
            watch_slots: Arc::new(tokio::sync::Semaphore::new((limit as usize).saturating_sub(2))),
        })
    }

    pub fn with_policy(mut self, policy: Policy) -> Imap<T> {
        self.policy = policy;
        self
    }

    /// Says the account has signed in before, so a refusal means the credentials went bad
    /// rather than were typed wrong.
    pub fn verified(self) -> Imap<T> {
        self.verified.store(true, Ordering::Relaxed);
        self
    }

    /// Replaces the TLS settings, for servers whose certificate the system does not know.
    pub fn with_tls(mut self, tls: Arc<ClientConfig>) -> Imap<T> {
        self.tls = tls;
        self
    }

    fn report(&self, failure: AuthFailure) {
        let event = {
            let mut account = self.account.lock().unwrap();
            self.signin
                .lock()
                .unwrap()
                .report_failure(&mut account, failure, SystemTime::now())
        };
        if let Some(e) = event {
            let _ = self.updates.send(Update::SignIn(e));
        }
    }

    /// Opens a connection and signs in. An account that needs a new sign-in is left alone
    /// until its hourly retry comes round.
    pub async fn connect(&self) -> Result<Connection> {
        let id = self.account.lock().unwrap().id.clone();
        {
            let mut s = self.signin.lock().unwrap();
            if s.work_paused(&id) && !s.try_retry(&id, SystemTime::now()) {
                return Err(Error::Paused);
            }
        }
        let credential = if self.server.provider.uses_microsoft_sign_in() {
            match self.tokens.access_token(&id, Resource::Mail).await {
                Ok(t) => Credential::OAuth(t),
                Err(e) => {
                    return Err(match AuthFailure::from_token_error(&e) {
                        Some(f) => {
                            self.report(f);
                            Error::Auth(f)
                        }
                        None => match e {
                            TokenError::Failed(text) => Error::Busy(text),
                            TokenError::InteractionRequired => unreachable!("reported above"),
                        },
                    })
                }
            }
        } else {
            match &self.password {
                Some(p) => Credential::Password(p.clone()),
                None => {
                    self.report(AuthFailure::AppPasswordRequired);
                    return Err(Error::Auth(AuthFailure::AppPasswordRequired));
                }
            }
        };
        let permit = tokio::time::timeout(
            PERMIT_WAIT,
            self.connections.clone().acquire_owned(),
        )
        .await
        .map_err(|_| Error::Busy("every connection of the account is in use".into()))?
        .expect("the semaphore is never closed");
        let worked = self.verified.load(Ordering::Relaxed);
        match Connection::open(&self.server, &credential, &self.tls, worked).await {
            Ok(mut conn) => {
                self.signin.lock().unwrap().report_success(&id);
                self.verified.store(true, Ordering::Relaxed);
                conn.permit = Some(permit);
                Ok(conn)
            }
            Err(Error::Auth(f)) => {
                self.report(f);
                Err(Error::Auth(f))
            }
            Err(e) => Err(e),
        }
    }

    /// Syncs every folder once on a new connection.
    pub async fn sync(&self) -> Result<Summary> {
        let mut conn = self.connect().await?;
        let summary = self.sync_all(&mut conn).await;
        conn.logout().await;
        summary
    }

    /// Syncs every folder on an open connection, the Inbox first.
    pub async fn sync_all(&self, conn: &mut Connection) -> Result<Summary> {
        let _one_at_a_time = self.sync_lock.lock().await;
        let folders = folders::refresh(conn, &self.store).await?;
        let mut total = Summary::default();
        let mut all_looked_at = true;
        for f in &folders {
            match self.sync_one(conn, f).await {
                Ok(s) => total.add(s),
                // A folder the server refuses or answers oddly must not hold the others back
                // or make the connection start over.
                Err(e @ (Error::Refused(_) | Error::Protocol(_))) => {
                    all_looked_at = false;
                    let _ = self.updates.send(Update::FolderFailed {
                        folder: f.name.clone(),
                        reason: e.to_string(),
                    });
                }
                Err(e) => return Err(e),
            }
        }
        if self.server.gmail && all_looked_at {
            total.removed += drop_unplaced(&self.store)?;
        }
        Ok(total)
    }

    async fn sync_one(&self, conn: &mut Connection, f: &lazymail_store::Folder) -> Result<Summary> {
        let tx = self.updates.clone();
        let mut progress = move |p: Progress| {
            let _ = tx.send(Update::Progress(p));
        };
        let summary = sync_folder(
            conn,
            &self.store,
            f,
            &self.policy,
            unix_now(),
            &mut progress,
        )
        .await?;
        let _ = self.updates.send(Update::Synced {
            folder: f.name.clone(),
            summary,
        });
        Ok(summary)
    }

    // After a wake-up only the folder that was watched is checked; Gmail's mail lives in
    // folders other than the Inbox it idles on, so all three are.
    async fn sync_watched(&self, conn: &mut Connection, folder: &str) -> Result<()> {
        if self.server.gmail {
            self.sync_all(conn).await?;
            return Ok(());
        }
        let _one_at_a_time = self.sync_lock.lock().await;
        let row = self
            .store
            .lock()
            .unwrap()
            .folders()?
            .into_iter()
            .find(|f| f.name == folder);
        if let Some(row) = row {
            self.sync_one(conn, &row).await?;
        }
        Ok(())
    }

    /// Syncs everything, then follows the Inbox through IDLE until `stop` is notified.
    /// Failures are retried with a growing pause; a sign-in problem waits for the hourly
    /// retry and Gmail's download limit for the next day, saying so through `Update`.
    pub async fn run(&self, stop: &Stop) {
        self.keep_running(stop, None).await
    }

    /// Follows one more open folder through IDLE on a connection of its own. Gmail idles on
    /// the Inbox only, so for Gmail this returns at once, and so it does when the account has no
    /// connection to spare: the account's limit less one for the main session and one kept free
    /// for actions.
    pub async fn watch(&self, folder: &str, stop: &Stop) {
        if self.server.gmail {
            return;
        }
        let Ok(_slot) = self.watch_slots.try_acquire() else {
            return;
        };
        self.keep_running(stop, Some(folder)).await
    }

    async fn keep_running(&self, stop: &Stop, folder: Option<&str>) {
        let mut backoff = Backoff::default();
        loop {
            let wait = match self.session(stop, folder, &mut backoff).await {
                Ok(()) => return,
                Err(Error::Stopped | Error::Auth(AuthFailure::GraphNeeded)) => return,
                Err(Error::Auth(_)) => RETRY_INTERVAL,
                Err(Error::Paused) => PAUSED_CHECK,
                Err(Error::DownloadLimit) => {
                    let _ = self.updates.send(Update::DownloadLimit {
                        resume_at: SystemTime::now() + DAY,
                    });
                    DAY
                }
                Err(_) => backoff.wait(),
            };
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = stop.stopped() => return,
            }
        }
    }

    async fn session(
        &self,
        stop: &Stop,
        folder: Option<&str>,
        backoff: &mut Backoff,
    ) -> Result<()> {
        let mut conn = stop.guard(self.connect()).await?;
        let watched = folder.unwrap_or("INBOX");
        if folder.is_none() {
            stop.guard(self.sync_all(&mut conn)).await?;
        } else {
            stop.guard(self.sync_watched(&mut conn, watched)).await?;
        }
        // What the folder looked like at the last sync. A change that lands between the sync
        // and the IDLE shows up in the next SELECT, so it is not slept through.
        let mut synced = None;
        loop {
            let sel = conn.select(watched).await?;
            let now = (sel.validity, sel.uidnext, sel.exists, sel.modseq);
            if synced != Some(now) {
                stop.guard(self.sync_watched(&mut conn, watched)).await?;
                synced = Some(now);
                continue;
            }
            // Only a connection that is synced and settled starts the pauses over, so a failure
            // that comes back every time does not log in again once a second.
            backoff.reset();
            if !conn.caps.idle {
                tokio::select! {
                    _ = tokio::time::sleep(POLL) => {}
                    _ = stop.stopped() => return Ok(()),
                }
                synced = None;
            } else {
                match conn.idle(IDLE_MAX, stop).await? {
                    IdleEnd::Stopped => {
                        conn.logout().await;
                        return Ok(());
                    }
                    // Flag changes leave no trace in the SELECT of a server without CONDSTORE.
                    IdleEnd::Changed => synced = None,
                    IdleEnd::Timeout => {}
                }
            }
        }
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_five_minutes_and_resets() {
        let mut b = Backoff::default();
        let waits: Vec<u64> = (0..11).map(|_| b.wait().as_secs()).collect();
        assert_eq!(waits, [1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300]);
        b.reset();
        assert_eq!(b.wait().as_secs(), 1);
    }
}
