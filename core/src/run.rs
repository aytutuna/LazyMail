use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use lazymail_accounts::{MailAccess, RETRY_INTERVAL};
use lazymail_imap::Stop;

use crate::shared::{AccountRt, Shared};
use crate::types::CoreEvent;

const POLL: Duration = Duration::from_secs(60);
const LEASE_RENEW: Duration = Duration::from_secs(4 * 60);

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

async fn pause(stop: &Stop, wait: Duration) {
    tokio::select! {
        _ = tokio::time::sleep(wait) => {}
        _ = stop.stopped() => {}
    }
}

impl Shared {
    /// Starts keeping every account up to date, and the settings, on threads of their own.
    pub(crate) fn start(self: &Arc<Self>) {
        let accounts = self.accounts.lock().unwrap().clone();
        for acc in &accounts {
            self.start_account(acc);
        }
        let mut thread = self.settings_thread.lock().unwrap();
        if thread.is_none() {
            let stop = Stop::new();
            let (me, s) = (self.clone(), stop.clone());
            let handle = std::thread::Builder::new()
                .name("lazymail-settings".into())
                .spawn(move || runtime().block_on(settings_loop(me, s)))
                .expect("settings thread");
            *thread = Some((stop, handle));
        }
    }

    pub(crate) fn is_running(&self) -> bool {
        self.settings_thread.lock().unwrap().is_some()
    }

    pub(crate) fn start_account(self: &Arc<Self>, acc: &Arc<AccountRt>) {
        let mut thread = acc.thread.lock().unwrap();
        if thread.is_some() || acc.mode() == MailAccess::None {
            return;
        }
        let stop = Stop::new();
        *acc.stop.lock().unwrap() = stop.clone();
        let (me, a) = (self.clone(), acc.clone());
        let handle = std::thread::Builder::new()
            .name(format!("lazymail-{}", acc.id))
            .spawn(move || {
                runtime().block_on(async {
                    tokio::join!(mail_loop(&me, &a, &stop), outbox_loop(&me, &a, &stop));
                })
            })
            .expect("account thread");
        *thread = Some(handle);
    }

    pub(crate) fn stop(&self) {
        let accounts = self.accounts.lock().unwrap().clone();
        for acc in &accounts {
            acc.stop.lock().unwrap().stop();
        }
        let settings = self.settings_thread.lock().unwrap().take();
        if let Some((stop, _)) = &settings {
            stop.stop();
        }
        for acc in &accounts {
            let t = acc.thread.lock().unwrap().take();
            if let Some(t) = t {
                let _ = t.join();
            }
        }
        if let Some((_, t)) = settings {
            let _ = t.join();
        }
    }
}

/// Keeps the account's mail current: IMAP follows the Inbox through IDLE, Graph is asked every
/// minute. An account that starts reading through Graph switches over.
async fn mail_loop(sh: &Arc<Shared>, acc: &Arc<AccountRt>, stop: &Stop) {
    while !stop.is_stopped() {
        match acc.mode() {
            MailAccess::Imap => match acc.imap() {
                Some(imap) => imap.run(stop).await,
                None => stop.stopped().await,
            },
            MailAccess::Graph => graph_loop(sh, acc, stop).await,
            MailAccess::None => stop.stopped().await,
        }
        pause(stop, Duration::from_secs(1)).await;
    }
}

async fn graph_loop(sh: &Arc<Shared>, acc: &Arc<AccountRt>, stop: &Stop) {
    while !stop.is_stopped() && acc.mode() == MailAccess::Graph {
        let paused = {
            let mut s = acc.signin.lock().unwrap();
            s.work_paused(&acc.id) && !s.try_retry(&acc.id, SystemTime::now())
        };
        let wait = if paused {
            POLL
        } else {
            match sh.sync_graph(acc).await {
                Ok(_) => POLL,
                Err(e) => {
                    sh.events.emit(CoreEvent::TaskFailed {
                        account_id: Some(acc.id.clone()),
                        detail: e.to_string(),
                    });
                    if matches!(e, crate::error::CoreError::SignIn { .. }) {
                        RETRY_INTERVAL
                    } else {
                        POLL
                    }
                }
            }
        };
        pause(stop, wait).await;
    }
}

async fn outbox_loop(sh: &Arc<Shared>, acc: &Arc<AccountRt>, stop: &Stop) {
    while !stop.is_stopped() {
        if let Err(e) = sh.run_outbox(acc).await {
            sh.events.emit(CoreEvent::TaskFailed {
                account_id: Some(acc.id.clone()),
                detail: e.to_string(),
            });
        }
        tokio::select! {
            _ = acc.wake.notified() => {}
            _ = tokio::time::sleep(POLL) => {}
            _ = stop.stopped() => {}
        }
    }
}

/// Reads what other devices wrote, tells about devices that want to join, and keeps the
/// lease for scheduled work.
async fn settings_loop(sh: Arc<Shared>, stop: Stop) {
    let mut announced = HashSet::new();
    let mut leased: Option<Instant> = None;
    while !stop.is_stopped() {
        if sh.settings_state() == crate::types::SettingsState::Ready {
            match sh.pull_settings().await {
                Ok(p) => {
                    if p.changed > 0 {
                        sh.events
                            .emit(CoreEvent::SettingsChanged { entries: p.changed });
                    }
                    if p.needs_rejoin {
                        sh.events.emit(CoreEvent::NeedsRejoin);
                    }
                }
                Err(e) => sh.events.emit(CoreEvent::TaskFailed {
                    account_id: sh.sync_account_id(),
                    detail: e.to_string(),
                }),
            }
            if let Ok(requests) = sh.join_requests().await {
                for q in requests {
                    if announced.insert(q.nonce.clone()) {
                        sh.events.emit(CoreEvent::JoinRequested {
                            device_id: q.device_id,
                            name: q.name,
                        });
                    }
                }
            }
            if leased.is_none_or(|t| t.elapsed() >= LEASE_RENEW) && sh.hold_lease().await.is_ok() {
                leased = Some(Instant::now());
            }
        }
        pause(&stop, POLL).await;
    }
}
