//! Against Dovecot and the SMTP sink from testdata/servers/start.sh. The tests are ignored
//! without them and run with `cargo test -- --include-ignored`.

mod common;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use base64::{engine::general_purpose::STANDARD, Engine};
use common::{open, Events, Time};
use lazymail_accounts::Provider;
use lazymail_core::{
    AccountSetup, ConnectionSecurity, Core, CoreError, CoreEvent, FlagSet, MailAddress,
    OutboxStatus, OutgoingMessage, ProviderKind, SearchRequest, ServerConfig, SettingsSetup,
    SettingsState,
};
use lazymail_imap::{Connection, Credential, Server, Transport};
use lazymail_store::Flags;
use tempfile::TempDir;

// Every test uses the same mailbox, so they take turns.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

struct Servers {
    imap: (String, u16),
    smtp: (String, u16),
    sink: PathBuf,
    cert: Vec<u8>,
    _turn: MutexGuard<'static, ()>,
}

fn addr(var: &str) -> (String, u16) {
    let v = std::env::var(var).unwrap_or_else(|_| panic!("{var} is not set"));
    let (h, p) = v.rsplit_once(':').unwrap();
    (h.to_string(), p.parse().unwrap())
}

fn servers() -> Servers {
    let turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let sink = PathBuf::from(std::env::var("LAZYMAIL_TEST_SMTP_DIR").expect("servers are not up"));
    // start.sh puts the certificate next to the sink's mail directory.
    let pem = std::fs::read_to_string(sink.parent().unwrap().join("cert.pem")).unwrap();
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let servers = Servers {
        imap: addr("LAZYMAIL_TEST_IMAP"),
        smtp: addr("LAZYMAIL_TEST_SMTP"),
        sink,
        cert: STANDARD.decode(b64).unwrap(),
        _turn: turn,
    };
    servers.wipe();
    servers
}

// The other tests expect the INBOX they find to be empty, so every test leaves it that way.
impl Drop for Servers {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl Servers {
    fn setup(&self) -> AccountSetup {
        AccountSetup {
            address: "alice@example.test".into(),
            name: "Alice".into(),
            provider: Some(ProviderKind::Other),
            password: Some("alice-pass".into()),
            server: Some(ServerConfig {
                imap_host: self.imap.0.clone(),
                imap_port: self.imap.1,
                imap_security: ConnectionSecurity::StartTls,
                smtp_host: self.smtp.0.clone(),
                smtp_port: self.smtp.1,
                smtp_security: ConnectionSecurity::StartTls,
                login_is_local_part: true,
            }),
            pinned_certificate: Some(self.cert.clone()),
            use_graph: false,
        }
    }

    /// Talks to Dovecot directly, outside the core, to set up what a test starts from.
    fn mailbox<T>(&self, work: impl AsyncFnOnce(&mut Connection) -> T) -> T {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let server = Server {
                host: self.imap.0.clone(),
                port: self.imap.1,
                transport: Transport::Plain,
                user: "alice".into(),
                provider: Provider::Other,
                gmail: false,
            };
            let tls = Arc::new(lazymail_accounts::tls_config());
            let mut conn = Connection::open(
                &server,
                &Credential::Password("alice-pass".into()),
                &tls,
                true,
            )
            .await
            .unwrap();
            let out = work(&mut conn).await;
            conn.logout().await;
            out
        })
    }

    fn deliver(&self, raw: String) {
        self.mailbox(async |c| {
            c.append_message("INBOX", raw.as_bytes(), Flags::default())
                .await
                .unwrap();
        });
    }

    /// Empties what the tests fill, and the settings folder, so the next device starts first.
    fn wipe(&self) {
        self.mailbox(async |c| {
            for folder in ["INBOX", "Sent", "Archive", lazymail_imap::SETTINGS_FOLDER] {
                for r in c.list_blobs(folder).await.unwrap() {
                    c.delete_blob(folder, r).await.unwrap();
                }
            }
        });
    }

    /// The files the sink took, whole.
    fn sunk(&self) -> Vec<String> {
        std::fs::read_dir(&self.sink)
            .unwrap()
            .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
            .collect()
    }
}

fn token() -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("zq{ms}")
}

fn mail(subject: &str, body: &str) -> String {
    format!(
        "From: Ann <ann@example.com>\r\nTo: alice@example.test\r\nSubject: {subject}\r\n\
         Date: Tue, 03 Jan 2023 10:00:00 +0000\r\nMessage-ID: <{}@example.com>\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n",
        token()
    )
}

fn events_until(events: &Events, found: impl Fn(&CoreEvent) -> bool) -> Vec<CoreEvent> {
    let mut seen = Vec::new();
    for _ in 0..50 {
        seen.extend(events.taken());
        if seen.iter().any(&found) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    seen
}

#[test]
#[ignore]
fn first_download_search_flags_and_moves() {
    let s = servers();
    let t = token();
    s.deliver(mail(
        &format!("Quarterly {t}"),
        &format!("the budget is ready {t}"),
    ));
    s.deliver(mail(&format!("Lunch {t}"), &format!("pizza at noon {t}")));

    let dir = TempDir::new().unwrap();
    let core = open(dir.path(), "laptop", &Time::now());
    let events = Events::default();
    core.set_listener(Some(Box::new(events.clone())));
    let account = core.add_account(s.setup()).unwrap().account;
    let id = account.id;

    let summary = core.sync_now(id.clone()).unwrap();
    assert!(summary.added >= 2, "{summary:?}");
    let seen = events_until(&events, |e| matches!(e, CoreEvent::FolderSynced { .. }));
    assert!(
        seen.iter().any(|e| matches!(e, CoreEvent::Progress { .. })),
        "{seen:?}"
    );

    let folders = core.folders(id.clone()).unwrap();
    let find = |name: &str| folders.iter().find(|f| f.name == name).unwrap().id;
    let inbox = find("INBOX");
    assert_eq!(
        folders
            .iter()
            .find(|f| f.id == inbox)
            .unwrap()
            .role
            .as_deref(),
        Some("inbox")
    );
    assert!(folders.iter().all(|f| f.name != "Alazy"));

    let hits = core
        .search(
            id.clone(),
            SearchRequest {
                text: t.clone(),
                ..SearchRequest::default()
            },
        )
        .unwrap();
    assert_eq!(hits.len(), 2, "{hits:?}");
    let budget = hits
        .iter()
        .find(|h| h.subject.starts_with("Quarterly"))
        .unwrap();
    let detail = core.message(id.clone(), budget.id).unwrap();
    assert!(detail.body_text.unwrap().contains("the budget is ready"));
    assert!(!detail.summary.flags.seen);

    // The server is told, and still has the flag after another sync.
    core.set_flags(
        id.clone(),
        budget.id,
        FlagSet {
            seen: true,
            ..FlagSet::default()
        },
    )
    .unwrap();
    core.sync_now(id.clone()).unwrap();
    assert!(
        core.message(id.clone(), budget.id)
            .unwrap()
            .summary
            .flags
            .seen
    );

    let archive = find("Archive");
    core.move_message(id.clone(), budget.id, archive).unwrap();
    core.sync_now(id.clone()).unwrap();
    let in_archive = core.messages(id.clone(), archive, 0, 50).unwrap();
    assert!(in_archive.iter().any(|m| m.id == budget.id));
    let in_inbox = core.messages(id.clone(), inbox, 0, 500).unwrap();
    assert!(in_inbox.iter().all(|m| m.id != budget.id));
    assert!(in_inbox.iter().any(|m| m.subject.starts_with("Lunch")));
}

#[test]
#[ignore]
fn mail_goes_out_through_the_outbox_and_a_copy_lands_in_sent() {
    let s = servers();
    let t = token();
    let dir = TempDir::new().unwrap();
    let time = Time::now();
    let core = open(dir.path(), "laptop", &time);
    let id = core.add_account(s.setup()).unwrap().account.id;
    core.sync_now(id.clone()).unwrap();

    let queued = core
        .send(
            id.clone(),
            OutgoingMessage {
                from: None,
                to: vec![MailAddress {
                    name: Some("Bob".into()),
                    email: "bob@example.test".into(),
                }],
                cc: vec![],
                bcc: vec![],
                subject: format!("Ping {t}"),
                text: Some(format!("see you {t}")),
                html: None,
                attachments: vec![],
                in_reply_to: None,
                references: vec![],
            },
        )
        .unwrap();
    assert_eq!(queued.status, OutboxStatus::Queued);

    let report = core.run_outbox(id.clone()).unwrap();
    assert_eq!(
        report.sent,
        1,
        "{report:?} {:?}",
        core.outbox(id.clone()).unwrap()
    );
    let delivered: Vec<_> = s
        .sunk()
        .into_iter()
        .filter(|f| f.contains(&format!("Message-ID: {}\r\n", queued.message_id)))
        .collect();
    assert_eq!(delivered.len(), 1);
    assert!(delivered[0].contains("X-Sink-From: <alice@example.test>"));
    assert!(delivered[0].contains("X-Sink-To: <bob@example.test>"));

    // The server does not file a Sent copy, so the app does once it has waited.
    let waiting = core.outbox(id.clone()).unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].status, OutboxStatus::Sent);
    time.advance_secs(31);
    core.run_outbox(id.clone()).unwrap();
    assert!(core.outbox(id.clone()).unwrap().is_empty());

    core.sync_now(id.clone()).unwrap();
    let sent = core
        .folders(id.clone())
        .unwrap()
        .into_iter()
        .find(|f| f.role.as_deref() == Some("sent"))
        .unwrap();
    let copies = core
        .search(
            id.clone(),
            SearchRequest {
                text: t,
                folder_id: Some(sent.id),
                ..SearchRequest::default()
            },
        )
        .unwrap();
    assert_eq!(copies.len(), 1, "{copies:?}");
    assert!(copies[0].flags.seen);
}

/// Adds the shared mailbox to a core that is not the first device.
fn second_device(s: &Servers, dir: &TempDir, time: &Time, name: &str) -> (Core, String) {
    let core = open(dir.path(), name, time);
    let added = core.add_account(s.setup()).unwrap();
    assert_eq!(added.settings, Some(SettingsSetup::MustJoin));
    (core, added.account.id)
}

#[test]
#[ignore]
fn a_setting_reaches_a_second_device_after_it_joins_with_the_code() {
    let s = servers();
    let time = Time::now();

    let dir_a = TempDir::new().unwrap();
    let a = open(dir_a.path(), "laptop", &time);
    let added = a.add_account(s.setup()).unwrap();
    let Some(SettingsSetup::Created { recovery_code }) = added.settings else {
        panic!("{:?}", added.settings);
    };
    assert!(added.account.is_sync_account);
    assert_eq!(a.settings_state(), SettingsState::Ready);
    a.set_setting("theme".into(), "dark".into()).unwrap();

    let dir_b = TempDir::new().unwrap();
    let (b, _) = second_device(&s, &dir_b, &time, "phone");
    assert_eq!(b.settings_state(), SettingsState::NoKey);
    assert!(b.setting("theme".into()).is_err());

    // The new device asks, the laptop offers, and each shows a code for the other.
    b.request_join().unwrap();
    let request = a.join_requests().unwrap().pop().unwrap();
    assert_eq!(request.name, "phone");
    a.offer_join(request.nonce.clone()).unwrap();
    let offer = b.join_offers().unwrap().pop().unwrap();
    assert_eq!(offer.name, "laptop");
    let shown_on_laptop = a.join_code(request.nonce.clone()).unwrap();
    assert_eq!(offer.code, shown_on_laptop);

    let wrong = if shown_on_laptop == "0000" {
        "1111"
    } else {
        "0000"
    };
    assert!(b
        .finish_join(offer.device_id.clone(), wrong.into())
        .is_err());
    a.approve_join(request.nonce, offer.code.clone()).unwrap();
    b.finish_join(offer.device_id, shown_on_laptop).unwrap();

    assert_eq!(b.settings_state(), SettingsState::Ready);
    assert_eq!(b.setting("theme".into()).unwrap().as_deref(), Some("dark"));
    b.set_setting("theme".into(), "light".into()).unwrap();
    b.set_setting("font".into(), "serif".into()).unwrap();
    a.pull_settings().unwrap();
    assert_eq!(a.setting("theme".into()).unwrap().as_deref(), Some("light"));
    assert_eq!(a.settings().unwrap().len(), 2);
    assert_eq!(a.devices().unwrap().len(), 2);
    assert!(a.devices().unwrap().iter().any(|d| d.name == "phone"));

    // The key survives a restart, and the printed code opens it on a third device.
    drop(b);
    let b = open(dir_b.path(), "phone", &time);
    assert_eq!(b.settings_state(), SettingsState::Ready);
    assert_eq!(b.setting("font".into()).unwrap().as_deref(), Some("serif"));

    let dir_c = TempDir::new().unwrap();
    let (c, _) = second_device(&s, &dir_c, &time, "tablet");
    assert!(c
        .recover("0000-0000-0000-0000-0000-0000-0000-0000".into())
        .is_err());
    c.recover(recovery_code).unwrap();
    assert_eq!(c.setting("font".into()).unwrap().as_deref(), Some("serif"));

    // Removing the phone ends its key; the laptop and the tablet carry on.
    let keep: Vec<String> = a
        .devices()
        .unwrap()
        .into_iter()
        .filter(|d| d.name != "phone")
        .map(|d| d.id)
        .collect();
    let phone = a
        .devices()
        .unwrap()
        .into_iter()
        .find(|d| d.name == "phone")
        .unwrap();
    a.remove_device(phone.id, keep).unwrap();
    a.set_setting("after".into(), "removal".into()).unwrap();
    c.pull_settings().unwrap();
    assert_eq!(
        c.setting("after".into()).unwrap().as_deref(),
        Some("removal")
    );
}

#[test]
#[ignore]
fn the_lease_moves_to_another_device_when_the_main_computer_goes_quiet() {
    let s = servers();
    let time = Time::now();

    let dir_a = TempDir::new().unwrap();
    let a = open(dir_a.path(), "desktop", &time);
    a.add_account(s.setup()).unwrap();
    let dir_b = TempDir::new().unwrap();
    let (b, _) = second_device(&s, &dir_b, &time, "laptop");
    b.request_join().unwrap();
    let request = a.join_requests().unwrap().pop().unwrap();
    a.offer_join(request.nonce.clone()).unwrap();
    let offer = b.join_offers().unwrap().pop().unwrap();
    let shown = a.join_code(request.nonce.clone()).unwrap();
    a.approve_join(request.nonce, offer.code).unwrap();
    b.finish_join(offer.device_id, shown).unwrap();

    let desktop = a
        .devices()
        .unwrap()
        .into_iter()
        .find(|d| d.is_this_device)
        .unwrap()
        .id;
    a.set_main_computer(Some(desktop.clone())).unwrap();
    assert_eq!(
        b.main_computer().unwrap().as_deref(),
        Some(desktop.as_str())
    );

    assert!(a.hold_lease().unwrap());
    assert!(!b.hold_lease().unwrap());
    assert_eq!(b.lease_holder().unwrap().as_deref(), Some(desktop.as_str()));

    // The desktop stops renewing; after the lease and its margin the laptop takes over.
    time.advance_secs(13 * 60);
    assert!(b.hold_lease().unwrap());

    // When the main computer is back it asks the holder to step aside and holds from its next call.
    assert!(!a.hold_lease().unwrap());
    assert!(!b.hold_lease().unwrap());
    assert!(a.hold_lease().unwrap());
    a.drop_lease().unwrap();
}

#[test]
#[ignore]
fn background_sync_follows_the_inbox_and_empties_the_outbox() {
    let s = servers();
    let t = token();
    let dir = TempDir::new().unwrap();
    let core = open(dir.path(), "laptop", &Time::now());
    let events = Events::default();
    core.set_listener(Some(Box::new(events.clone())));
    let id = core.add_account(s.setup()).unwrap().account.id;
    core.start_sync();
    events_until(&events, |e| matches!(e, CoreEvent::FolderSynced { .. }));

    // New mail reaches the store without a call asking for it.
    s.deliver(mail(&format!("Arrived {t}"), "while syncing"));
    let search = || {
        core.search(
            id.clone(),
            SearchRequest {
                text: t.clone(),
                ..SearchRequest::default()
            },
        )
        .unwrap()
    };
    wait_for(|| !search().is_empty());

    let queued = core
        .send(
            id.clone(),
            OutgoingMessage {
                from: None,
                to: vec![MailAddress {
                    name: None,
                    email: "bob@example.test".into(),
                }],
                cc: vec![],
                bcc: vec![],
                subject: format!("Background {t}"),
                text: Some("hello".into()),
                html: None,
                attachments: vec![],
                in_reply_to: None,
                references: vec![],
            },
        )
        .unwrap();
    wait_for(|| {
        s.sunk()
            .iter()
            .any(|f| f.contains(&format!("Message-ID: {}\r\n", queued.message_id)))
    });
    core.stop_sync();
}

fn wait_for(done: impl Fn() -> bool) {
    for _ in 0..100 {
        if done() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("nothing happened within 10 seconds");
}

#[test]
#[ignore]
fn a_certificate_that_is_not_the_confirmed_one_is_refused() {
    let s = servers();
    let dir = TempDir::new().unwrap();
    let core = open(dir.path(), "laptop", &Time::now());
    let mut setup = s.setup();
    setup.pinned_certificate = Some(vec![1, 2, 3]);
    let err = core.add_account(setup).unwrap_err();
    assert!(matches!(err, CoreError::Network { .. }), "{err:?}");
    assert!(core.accounts().is_empty());

    let mut wrong_password = s.setup();
    wrong_password.password = Some("not-the-password".into());
    let err = core.add_account(wrong_password).unwrap_err();
    assert!(matches!(err, CoreError::SignIn { .. }), "{err:?}");
    assert!(core.accounts().is_empty());
}
