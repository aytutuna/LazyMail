use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, Weak};
use std::thread::JoinHandle;
use std::time::SystemTime;

use base64::{engine::general_purpose::STANDARD, Engine};
use lazymail_accounts::{Account, AuthFailure, Event, MailAccess, SignIn};
use lazymail_graph::Graph;
use lazymail_imap::{Imap, Stop, Update};
use lazymail_store::{load_or_create_key, Store, Wrapper};
use lazymail_sync::{Clock, Identity, Replica, SettingsKey};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::sync::Notify;

use crate::callbacks::{EventListener, Tokens, Wrap};
use crate::error::{CoreError, Result};
use crate::mailfolder::AccountFolder;
use crate::pin::pinned_config;
use crate::types::{
    AccountInfo, AccountStatus, CoreEvent, MailAccessKind, OutboxReport, SyncPhase, SyncSummary,
};

const DEVICE_FILE: &str = "device.bin";
const DEVICE_AAD: &[u8] = b"device";

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// What this device keeps about itself, wrapped by the device key.
#[derive(Serialize, Deserialize)]
pub(crate) struct DeviceState {
    pub name: String,
    pub x_seed: [u8; 32],
    pub ed_seed: [u8; 32],
    /// The account whose mailbox carries the synced settings.
    pub sync_account: Option<String>,
    /// The settings key, base64 of `SettingsKey::to_secret`.
    pub settings_key: Option<String>,
}

impl DeviceState {
    fn load_or_create(dir: &Path, name: &str, wrapper: &Wrap) -> Result<DeviceState> {
        let path = dir.join(DEVICE_FILE);
        match std::fs::read(&path) {
            Ok(b) => {
                let plain = wrapper.unwrap(DEVICE_AAD, &b)?;
                serde_json::from_slice(&plain).map_err(|_| CoreError::Storage {
                    detail: "the device file is damaged".into(),
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut x_seed = [0u8; 32];
                let mut ed_seed = [0u8; 32];
                getrandom::fill(&mut x_seed)
                    .and(getrandom::fill(&mut ed_seed))
                    .map_err(|e| CoreError::Storage {
                        detail: e.to_string(),
                    })?;
                let state = DeviceState {
                    name: name.to_string(),
                    x_seed,
                    ed_seed,
                    sync_account: None,
                    settings_key: None,
                };
                state.save(dir, wrapper)?;
                Ok(state)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self, dir: &Path, wrapper: &Wrap) -> Result<()> {
        let plain = serde_json::to_vec(self).expect("plain data serializes");
        let wrapped = wrapper.wrap(DEVICE_AAD, &plain)?;
        let path = dir.join(DEVICE_FILE);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, wrapped)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub(crate) fn identity(&self) -> Identity {
        Identity::from_seeds(&self.name, self.x_seed, self.ed_seed)
    }

    pub(crate) fn key(&self) -> Option<SettingsKey> {
        let raw = STANDARD.decode(self.settings_key.as_ref()?).ok()?;
        SettingsKey::from_secret(&raw).ok()
    }
}

/// Delivers events from a thread of its own, outside any runtime, so a handler may call back
/// into the core.
#[derive(Clone)]
pub(crate) struct Events {
    tx: Sender<CoreEvent>,
    listener: Arc<Mutex<Option<Arc<dyn EventListener>>>>,
}

impl Events {
    fn new() -> Events {
        let (tx, rx) = std::sync::mpsc::channel::<CoreEvent>();
        let listener: Arc<Mutex<Option<Arc<dyn EventListener>>>> = Arc::default();
        let current = listener.clone();
        std::thread::Builder::new()
            .name("lazymail-events".into())
            .spawn(move || {
                for event in rx {
                    let l = current.lock().unwrap().clone();
                    if let Some(l) = l {
                        l.on_event(event);
                    }
                }
            })
            .expect("event thread");
        Events { tx, listener }
    }

    pub(crate) fn set(&self, l: Option<Arc<dyn EventListener>>) {
        *self.listener.lock().unwrap() = l;
    }

    pub(crate) fn emit(&self, e: CoreEvent) {
        let _ = self.tx.send(e);
    }
}

/// One account at run time. Its store is opened twice: the shared handle is for short locks
/// and the IMAP crate, and `open_store` gives work that holds a store across awaits its own.
pub(crate) struct AccountRt {
    pub id: String,
    pub dir: PathBuf,
    pub account: Arc<Mutex<Account>>,
    pub signin: Arc<Mutex<SignIn>>,
    pub store: Arc<Mutex<Store>>,
    pub pinned: Option<Vec<u8>>,
    pub imap: Mutex<Option<Arc<Imap<Tokens>>>>,
    pub graph: Arc<Graph<Tokens>>,
    /// Rung when something is queued in the Outbox.
    pub wake: Arc<Notify>,
    pub stop: Mutex<Stop>,
    pub thread: Mutex<Option<JoinHandle<()>>>,
}

impl AccountRt {
    pub(crate) fn mode(&self) -> MailAccess {
        self.account.lock().unwrap().mail
    }

    pub(crate) fn imap(&self) -> Option<Arc<Imap<Tokens>>> {
        self.imap.lock().unwrap().clone()
    }

    pub(crate) fn password(&self) -> Option<String> {
        let s = self.store.lock().unwrap();
        let p = s.secret("password").ok()??;
        String::from_utf8(p).ok()
    }

    /// Writes the account and its sign-in state to the store, so a restart keeps them.
    pub(crate) fn save(&self) -> Result<()> {
        let account = serde_json::to_vec(&*self.account.lock().unwrap()).expect("plain data");
        let signin = serde_json::to_vec(&*self.signin.lock().unwrap()).expect("plain data");
        let s = self.store.lock().unwrap();
        s.set_secret("account", &account)?;
        s.set_secret("signin", &signin)?;
        Ok(())
    }

    pub(crate) fn info(&self, sync_account: Option<&str>) -> AccountInfo {
        let a = self.account.lock().unwrap();
        let status = match self.signin.lock().unwrap().state(&a.id) {
            lazymail_accounts::AccountState::SignedIn => AccountStatus::SignedIn,
            lazymail_accounts::AccountState::NeedsSignIn { reason, .. } => {
                AccountStatus::NeedsSignIn {
                    reason: reason.message().to_string(),
                }
            }
        };
        AccountInfo {
            id: a.id.clone(),
            address: a.address.clone(),
            name: a.identities[0].name.clone(),
            provider: a.provider.into(),
            mail: match a.mail {
                MailAccess::Imap => MailAccessKind::Imap,
                MailAccess::Graph => MailAccessKind::Graph,
                MailAccess::None => MailAccessKind::Local,
            },
            status,
            is_sync_account: sync_account == Some(a.id.as_str()),
        }
    }
}

/// What every call and every background thread works on.
pub(crate) struct Shared {
    pub dir: PathBuf,
    pub wrapper: Arc<Wrap>,
    pub tokens: Tokens,
    pub events: Events,
    pub clock: Clock,
    pub handle: tokio::runtime::Handle,
    pub device: Mutex<DeviceState>,
    pub accounts: Mutex<Vec<Arc<AccountRt>>>,
    pub replica: tokio::sync::Mutex<Option<(MailAccess, Replica<AccountFolder>)>>,
    pub lease_held: AtomicBool,
    pub needs_rejoin: AtomicBool,
}

impl Shared {
    /// Seconds since the epoch on the device's clock.
    pub(crate) fn now(&self) -> i64 {
        (self.clock)() as i64 / 1000
    }

    pub(crate) fn open(
        dir: &Path,
        device_name: &str,
        wrapper: Wrap,
        tokens: Tokens,
        clock: Clock,
        handle: tokio::runtime::Handle,
    ) -> Result<Arc<Shared>> {
        std::fs::create_dir_all(dir.join("accounts"))?;
        let wrapper = Arc::new(wrapper);
        let device = DeviceState::load_or_create(dir, device_name, &wrapper)?;
        let shared = Arc::new(Shared {
            dir: dir.to_path_buf(),
            wrapper,
            tokens,
            events: Events::new(),
            clock,
            handle,
            device: Mutex::new(device),
            accounts: Mutex::default(),
            replica: tokio::sync::Mutex::new(None),
            lease_held: AtomicBool::new(false),
            needs_rejoin: AtomicBool::new(false),
        });
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir.join("accounts"))? {
            let path = entry?.path();
            if path.join("mail.db").exists() {
                found.extend(shared.open_account(&path)?);
            }
        }
        found.sort_by(|a, b| a.id.cmp(&b.id));
        *shared.accounts.lock().unwrap() = found;
        Ok(shared)
    }

    fn store_key(&self, dir: &Path) -> Result<lazymail_store::StoreKey> {
        Ok(load_or_create_key(
            &dir.join("store.key"),
            self.wrapper.as_ref(),
        )?)
    }

    /// Opens a second handle on the account's store, for work that keeps it across awaits.
    pub(crate) fn open_store(&self, acc: &AccountRt) -> Result<Store> {
        let key = self.store_key(&acc.dir)?;
        let wrapper: Arc<dyn Wrapper> = self.wrapper.clone();
        Ok(Store::open(&acc.dir, &key, wrapper)?)
    }

    /// `None` for a folder whose account was never saved, left by a crash while adding it.
    fn open_account(self: &Arc<Self>, dir: &Path) -> Result<Option<Arc<AccountRt>>> {
        let key = self.store_key(dir)?;
        let wrapper: Arc<dyn Wrapper> = self.wrapper.clone();
        let store = Store::open(dir, &key, wrapper)?;
        let Some(saved) = store.secret("account")? else {
            drop(store);
            std::fs::remove_dir_all(dir)?;
            return Ok(None);
        };
        let account: Account = serde_json::from_slice(&saved).map_err(|_| CoreError::Storage {
            detail: "the account record is damaged".into(),
        })?;
        let signin: SignIn = store
            .secret("signin")?
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let pinned = store.secret("pin")?;
        let verified =
            store.secret("password")?.is_some() || account.provider.uses_microsoft_sign_in();
        Ok(Some(
            self.assemble(dir, account, signin, store, pinned, verified),
        ))
    }

    /// Wires up a loaded or new account: the IMAP side when it has one, Graph, and the task that
    /// passes the IMAP side's updates on as events.
    pub(crate) fn assemble(
        self: &Arc<Self>,
        dir: &Path,
        account: Account,
        signin: SignIn,
        store: Store,
        pinned: Option<Vec<u8>>,
        verified: bool,
    ) -> Arc<AccountRt> {
        let id = account.id.clone();
        let acc = Arc::new(AccountRt {
            id: id.clone(),
            dir: dir.to_path_buf(),
            account: Arc::new(Mutex::new(account)),
            signin: Arc::new(Mutex::new(signin)),
            store: Arc::new(Mutex::new(store)),
            pinned,
            imap: Mutex::new(None),
            graph: Arc::new(Graph::new(&id, self.tokens.clone())),
            wake: Arc::new(Notify::new()),
            stop: Mutex::new(Stop::new()),
            thread: Mutex::new(None),
        });
        self.build_imap(&acc, verified);
        acc
    }

    /// Makes the account's IMAP side with the password stored now. Does nothing for an account
    /// that has no IMAP server.
    pub(crate) fn build_imap(self: &Arc<Self>, acc: &Arc<AccountRt>, verified: bool) {
        let (tx, rx) = unbounded_channel();
        let Some(mut imap) = Imap::new(
            acc.account.clone(),
            acc.password(),
            Arc::new(self.tokens.clone()),
            acc.store.clone(),
            acc.signin.clone(),
            tx,
        ) else {
            *acc.imap.lock().unwrap() = None;
            return;
        };
        if let Some(der) = &acc.pinned {
            imap = imap.with_tls(pinned_config(der.clone()));
        }
        if verified {
            imap = imap.verified();
        }
        *acc.imap.lock().unwrap() = Some(Arc::new(imap));
        self.handle
            .spawn(forward(self.clone(), Arc::downgrade(acc), rx));
    }

    pub(crate) fn account(&self, id: &str) -> Result<Arc<AccountRt>> {
        self.accounts
            .lock()
            .unwrap()
            .iter()
            .find(|a| a.id == id)
            .cloned()
            .ok_or_else(|| crate::error::not_found(format!("account {id}")))
    }

    pub(crate) fn sync_account_id(&self) -> Option<String> {
        self.device.lock().unwrap().sync_account.clone()
    }

    /// Saves what a replica holds as the settings key when it differs from what is kept.
    pub(crate) fn keep_key(&self, replica: &Replica<AccountFolder>) -> Result<()> {
        let key = replica
            .key()
            .map(|k| STANDARD.encode(k.to_secret().as_slice()));
        let mut d = self.device.lock().unwrap();
        if d.settings_key != key {
            d.settings_key = key;
            d.save(&self.dir, &self.wrapper)?;
        }
        Ok(())
    }

    pub(crate) fn set_sync_account(&self, id: Option<String>) -> Result<()> {
        let mut d = self.device.lock().unwrap();
        d.sync_account = id;
        d.settings_key = None;
        d.save(&self.dir, &self.wrapper)
    }

    /// Tells the sign-in state about a failure and passes on what the person should hear.
    pub(crate) fn report_failure(&self, acc: &AccountRt, failure: AuthFailure) {
        let event = {
            let mut account = acc.account.lock().unwrap();
            acc.signin
                .lock()
                .unwrap()
                .report_failure(&mut account, failure, SystemTime::now())
        };
        if let Some(e) = event {
            self.sign_in_event(acc, e);
        }
    }

    pub(crate) fn sign_in_event(&self, acc: &AccountRt, e: Event) {
        let _ = acc.save();
        self.events.emit(match e {
            Event::NeedsSignIn { account_id, reason } => CoreEvent::NeedsSignIn {
                account_id,
                reason: reason.message().to_string(),
            },
            Event::UsesGraph { account_id } => CoreEvent::UsesGraph { account_id },
        });
    }

    pub(crate) fn emit_outbox(&self, acc: &AccountRt, report: OutboxReport) {
        if report != OutboxReport::default() {
            self.events.emit(CoreEvent::OutboxRan {
                account_id: acc.id.clone(),
                report,
            });
        }
    }
}

/// Turns what an account's IMAP side reports into events, and keeps its sign-in state saved.
async fn forward(shared: Arc<Shared>, acc: Weak<AccountRt>, mut rx: UnboundedReceiver<Update>) {
    while let Some(update) = rx.recv().await {
        let Some(acc) = acc.upgrade() else { break };
        let account_id = acc.id.clone();
        match update {
            Update::SignIn(e) => shared.sign_in_event(&acc, e),
            Update::Progress(p) => shared.events.emit(CoreEvent::Progress {
                account_id,
                folder: p.folder,
                phase: match p.phase {
                    lazymail_imap::Phase::Headers => SyncPhase::Headers,
                    lazymail_imap::Phase::Bodies => SyncPhase::Bodies,
                },
                done: p.done,
                total: p.total,
                per_second: p.per_second,
                remaining_seconds: p.remaining.map(|d| d.as_secs()),
            }),
            Update::Synced { folder, summary } => shared.events.emit(CoreEvent::FolderSynced {
                account_id,
                folder,
                summary: SyncSummary {
                    added: summary.added,
                    removed: summary.removed,
                    changed: summary.changed,
                },
            }),
            Update::DownloadLimit { resume_at } => shared.events.emit(CoreEvent::DownloadLimit {
                account_id,
                resume_at: resume_at
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs() as i64),
            }),
            Update::FolderFailed { folder, reason } => {
                shared.events.emit(CoreEvent::FolderFailed {
                    account_id,
                    folder,
                    reason,
                })
            }
        }
    }
}
