//! Tests against Dovecot (set up by testdata/servers/start.sh; they skip without its variables
//! and run with `cargo test -- --include-ignored`) and against recorded-style transcripts.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use lazymail_accounts::{
    Account, AuthFailure, Endpoint, Login, Provider, Security, ServerSettings, SignIn, StaticTokens,
};
use lazymail_store::{Flags, Folder, Store, StoreKey, SyncState, TestWrapper};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tempfile::TempDir;
use tokio::sync::Notify;

use crate::conn::{Connection, Credential, Server, Transport};
use crate::folders;
use crate::sync::{sync_folder, Policy, Progress, Summary};
use crate::{Error, Imap, Update};

mod transcripts;

#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

// The test servers use a certificate made a minute ago.
fn trust_anything() -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    Arc::new(
        ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
            .with_no_client_auth(),
    )
}

struct Env {
    imap: (String, u16),
    imaps: (String, u16),
    user: String,
    pass: String,
}

fn addr(var: &str) -> Option<(String, u16)> {
    let v = std::env::var(var).ok()?;
    let (h, p) = v.rsplit_once(':')?;
    Some((h.to_string(), p.parse().ok()?))
}

fn env() -> Option<Env> {
    Some(Env {
        imap: addr("LAZYMAIL_TEST_IMAP")?,
        imaps: addr("LAZYMAIL_TEST_IMAPS")?,
        user: std::env::var("LAZYMAIL_TEST_USER2").ok()?,
        pass: std::env::var("LAZYMAIL_TEST_PASS2").ok()?,
    })
}

// One test at a time uses the server: it allows ten sessions per user, and Dovecot answers
// some CREATEs wrongly with ALREADYEXISTS when sessions create folders together.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

macro_rules! servers {
    ($env:ident) => {
        let Some($env) = env() else { return };
        let _turn = ONE_AT_A_TIME.lock().await;
    };
}

impl Env {
    fn server(&self, transport: Transport) -> Server {
        let (host, port) = match transport {
            Transport::Tls => &self.imaps,
            _ => &self.imap,
        };
        Server {
            host: host.clone(),
            port: *port,
            transport,
            user: self.user.clone(),
            provider: Provider::Other,
            gmail: false,
        }
    }

    async fn open(&self) -> Connection {
        Connection::open(
            &self.server(Transport::Plain),
            &Credential::Password(self.pass.clone()),
            &trust_anything(),
            true,
        )
        .await
        .unwrap()
    }

    fn account(&self) -> Account {
        let endpoint = |(host, port): &(String, u16)| Endpoint {
            host: host.clone(),
            port: *port,
            security: Security::Tls,
            login: Login::LocalPart,
        };
        let mut a = Account::new(
            "dovecot",
            Provider::Other,
            &format!("{}@example.test", self.user),
            "Alice",
        );
        a.settings = Some(ServerSettings {
            imap: endpoint(&self.imap),
            smtp: endpoint(&self.imap),
            files_sent: false,
            gmail: false,
            max_connections: 3,
        });
        a
    }
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn unique(prefix: &str) -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("{prefix}-{t}-{}", COUNTER.fetch_add(1, Ordering::Relaxed))
}

fn new_store(dir: &TempDir) -> Arc<Mutex<Store>> {
    let store = Store::open(
        dir.path(),
        &StoreKey::generate(),
        Arc::new(TestWrapper::new()),
    )
    .unwrap();
    Arc::new(Mutex::new(store))
}

const PDF: &[u8] = b"%PDF-1.4 fake\x00\x01\x02\xff end";

fn plain(subject: &str, id: &str, date: &str) -> Vec<u8> {
    format!(
        "From: Ann Example <ann@example.com>\r\nTo: Bob <bob@example.org>, carol@example.net\r\n\
         Cc: \"Dan\" <dan@example.org>\r\nSubject: {subject}\r\nDate: {date}\r\n\
         Message-ID: <{id}>\r\nIn-Reply-To: <root@example.com>\r\n\
         References: <root@example.com> <mid@example.com>\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\r\nHello from {subject}\r\n"
    )
    .into_bytes()
}

fn with_attachment(subject: &str, id: &str) -> Vec<u8> {
    format!(
        "From: Ann <ann@example.com>\r\nTo: bob@example.org\r\nSubject: {subject}\r\n\
         Date: Tue, 03 Jan 2023 10:00:00 +0000\r\nMessage-ID: <{id}>\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n\
         --b1\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\
         Content-Transfer-Encoding: quoted-printable\r\n\r\nCaf=E9 au lait\r\n\
         --b1\r\nContent-Type: application/pdf; name=\"=?utf-8?Q?r=C3=A9sum=C3=A9.pdf?=\"\r\n\
         Content-Disposition: attachment; filename=\"=?utf-8?Q?r=C3=A9sum=C3=A9.pdf?=\"\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n{}\r\n--b1--\r\n",
        STANDARD.encode(PDF)
    )
    .into_bytes()
}

fn html_only(subject: &str, id: &str) -> Vec<u8> {
    format!(
        "From: news@example.com\r\nTo: bob@example.org\r\nSubject: {subject}\r\n\
         Date: Wed, 04 Jan 2023 10:00:00 +0000\r\nMessage-ID: <{id}>\r\n\
         Content-Type: text/html; charset=utf-8\r\n\r\n<html><body><p>Big <b>news</b></p></body></html>\r\n"
    )
    .into_bytes()
}

fn alternative(subject: &str, id: &str) -> Vec<u8> {
    format!(
        "From: news@example.com\r\nTo: bob@example.org\r\nSubject: {subject}\r\n\
         Date: Thu, 05 Jan 2023 10:00:00 +0000\r\nMessage-ID: <{id}>\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/alternative; boundary=\"alt\"\r\n\r\n\
         --alt\r\nContent-Type: text/plain\r\n\r\nplain side\r\n\
         --alt\r\nContent-Type: text/html\r\n\r\n<p>html side</p>\r\n--alt--\r\n"
    )
    .into_bytes()
}

async fn sync_named(
    conn: &mut Connection,
    store: &Arc<Mutex<Store>>,
    name: &str,
    policy: &Policy,
) -> Summary {
    let folder = store.lock().unwrap().upsert_folder(name, None).unwrap();
    sync_folder(conn, store, &folder, policy, now(), &mut |_: Progress| {})
        .await
        .unwrap()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn folder_of(store: &Arc<Mutex<Store>>, name: &str) -> Folder {
    store
        .lock()
        .unwrap()
        .folders()
        .unwrap()
        .into_iter()
        .find(|f| f.name == name)
        .unwrap()
}

fn rows(store: &Arc<Mutex<Store>>, folder: &Folder) -> Vec<lazymail_store::Message> {
    let s = store.lock().unwrap();
    let mut out: Vec<_> = s
        .folder_uids(folder.id)
        .unwrap()
        .into_iter()
        .map(|(uid, _)| {
            let id = s.find_by_uid(folder.id, uid).unwrap().unwrap();
            s.message(id).unwrap().unwrap()
        })
        .collect();
    out.sort_by_key(|m| m.uid);
    out
}

#[tokio::test]
#[ignore]
async fn signs_in_over_plain_tls_and_starttls() {
    servers!(env);
    for transport in [Transport::Plain, Transport::Tls, Transport::StartTls] {
        let conn = Connection::open(
            &env.server(transport),
            &Credential::Password(env.pass.clone()),
            &trust_anything(),
            true,
        )
        .await
        .unwrap();
        assert!(conn.capabilities().idle, "{transport:?}");
        conn.logout().await;
    }
}

#[tokio::test]
#[ignore]
async fn a_wrong_password_is_a_sign_in_failure() {
    servers!(env);
    let err = Connection::open(
        &env.server(Transport::Plain),
        &Credential::Password("nope".into()),
        &trust_anything(),
        false,
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(err, Error::Auth(AuthFailure::Rejected)), "{err:?}");
}

#[tokio::test]
#[ignore]
async fn special_use_folders_get_their_roles() {
    servers!(env);
    let dir = TempDir::new().unwrap();
    let store = new_store(&dir);
    let mut conn = env.open().await;
    let wanted = folders::refresh(&mut conn, &store).await.unwrap();
    assert_eq!(wanted[0].name, "INBOX");
    let role = |n: &str| wanted.iter().find(|f| f.name == n).unwrap().role.clone();
    assert_eq!(role("INBOX").as_deref(), Some("inbox"));
    assert_eq!(role("Sent").as_deref(), Some("sent"));
    assert_eq!(role("Drafts").as_deref(), Some("drafts"));
    assert_eq!(role("Trash").as_deref(), Some("trash"));
    assert_eq!(role("Junk").as_deref(), Some("junk"));
    assert_eq!(role("Archive").as_deref(), Some("archive"));
}

#[tokio::test]
#[ignore]
async fn folders_that_leave_the_server_leave_the_store() {
    servers!(env);
    let dir = TempDir::new().unwrap();
    let store = new_store(&dir);
    let mut conn = env.open().await;
    let name = unique("Çalışma");
    create(&mut conn, &name).await;
    folders::refresh(&mut conn, &store).await.unwrap();
    assert!(store
        .lock()
        .unwrap()
        .folders()
        .unwrap()
        .iter()
        .any(|f| f.name == name));
    conn.exec(&format!(
        "DELETE {}",
        crate::conn::quote(&crate::utf7::encode(&name)).unwrap()
    ))
    .await
    .unwrap();
    folders::refresh(&mut conn, &store).await.unwrap();
    assert!(!store
        .lock()
        .unwrap()
        .folders()
        .unwrap()
        .iter()
        .any(|f| f.name == name));
}

#[derive(Debug, Clone, Copy)]
enum Mode {
    Qresync,
    Condstore,
    Ranges,
}

async fn lifecycle(mode: Mode) {
    servers!(env);
    let dir = TempDir::new().unwrap();
    let store = new_store(&dir);
    let mut conn = env.open().await;
    match mode {
        Mode::Qresync => assert!(conn.qresync_on, "the test server should offer QRESYNC"),
        Mode::Condstore => conn.qresync_on = false,
        Mode::Ranges => {
            conn.qresync_on = false;
            conn.caps.condstore = false;
        }
    }
    let name = unique("life");
    create(&mut conn, &name).await;
    let seen = Flags {
        seen: true,
        ..Default::default()
    };
    let old = plain(
        "old one",
        "old@example.com",
        "Wed, 01 Jan 2020 10:00:00 +0000",
    );
    for (m, flags) in [
        (
            plain("first", "m1@example.com", "Mon, 02 Jan 2023 10:00:00 +0000"),
            seen,
        ),
        (
            with_attachment("second", "m2@example.com"),
            Flags::default(),
        ),
        (html_only("third", "m3@example.com"), Flags::default()),
        (alternative("fourth", "m4@example.com"), Flags::default()),
        (old, Flags::default()),
    ] {
        conn.append_message(&name, &m, flags).await.unwrap();
    }

    let first = sync_named(&mut conn, &store, &name, &Policy::default()).await;
    assert_eq!(first.added, 5, "{mode:?}");
    let f = folder_of(&store, &name);
    assert!(f.sync.uidnext.is_some());
    let all = rows(&store, &f);
    assert_eq!(all.len(), 5);
    let m1 = &all[0];
    assert_eq!(m1.subject, "first");
    assert_eq!(
        (m1.from_name.as_str(), m1.from_addr.as_str()),
        ("Ann Example", "ann@example.com")
    );
    assert_eq!(m1.to, "Bob <bob@example.org>, carol@example.net");
    assert_eq!(m1.cc, "Dan <dan@example.org>");
    assert_eq!(m1.message_id.as_deref(), Some("m1@example.com"));
    assert_eq!(m1.in_reply_to.as_deref(), Some("root@example.com"));
    assert_eq!(m1.references, ["root@example.com", "mid@example.com"]);
    assert_eq!(m1.date, 1_672_653_600);
    assert!(m1.flags.seen);
    assert!(m1.headers.as_deref().unwrap().contains("Subject: first"));
    assert_eq!(m1.body_text.as_deref().unwrap().trim(), "Hello from first");
    assert!(!m1.has_attachments);

    let m2 = &all[1];
    assert_eq!(m2.body_text.as_deref().unwrap().trim(), "Café au lait");
    assert!(m2.has_attachments);
    assert_eq!(m2.attachments.len(), 1);
    assert_eq!(m2.attachments[0].filename, "résumé.pdf");
    assert_eq!(m2.attachments[0].mime, "application/pdf");
    assert_eq!(m2.attachments[0].part, "2");

    let m3 = &all[2];
    assert!(m3.body_html.as_deref().unwrap().contains("<b>news</b>"));
    let words: Vec<&str> = m3
        .body_text
        .as_deref()
        .unwrap()
        .split_whitespace()
        .collect();
    assert_eq!(words, ["Big", "news"]);
    let m4 = &all[3];
    assert_eq!(m4.body_text.as_deref().unwrap().trim(), "plain side");
    assert_eq!(m4.body_html.as_deref().unwrap().trim(), "<p>html side</p>");

    // Nothing happened since.
    assert_eq!(
        sync_named(&mut conn, &store, &name, &Policy::default()).await,
        Summary::default()
    );

    conn.append_message(
        &name,
        &plain("fifth", "m5@example.com", "Fri, 06 Jan 2023 10:00:00 +0000"),
        Flags::default(),
    )
    .await
    .unwrap();
    let s = sync_named(&mut conn, &store, &name, &Policy::default()).await;
    assert_eq!((s.added, s.removed), (1, 0), "{mode:?}");

    // Another session flags the second message and expunges the first.
    let mut other = env.open().await;
    other.select(&name).await.unwrap();
    let uid2 = all[1].uid.unwrap();
    let uid1 = all[0].uid.unwrap();
    other
        .exec(&format!("UID STORE {uid2} +FLAGS (\\Flagged \\Answered)"))
        .await
        .unwrap();
    other
        .exec(&format!("UID STORE {uid1} +FLAGS (\\Deleted)"))
        .await
        .unwrap();
    other.exec("EXPUNGE").await.unwrap();
    let s = sync_named(&mut conn, &store, &name, &Policy::default()).await;
    assert_eq!((s.added, s.removed, s.changed), (0, 1, 1), "{mode:?}");
    let now_rows = rows(&store, &f);
    assert_eq!(now_rows.len(), 5);
    let flagged = now_rows.iter().find(|m| m.uid == Some(uid2)).unwrap();
    assert!(flagged.flags.flagged && flagged.flags.answered);
    assert!(now_rows.iter().all(|m| m.uid != Some(uid1)));
    assert_eq!(
        sync_named(&mut conn, &store, &name, &Policy::default()).await,
        Summary::default()
    );
}

#[tokio::test]
#[ignore]
async fn follows_a_folder_with_qresync() {
    lifecycle(Mode::Qresync).await;
}

#[tokio::test]
#[ignore]
async fn follows_a_folder_with_condstore() {
    lifecycle(Mode::Condstore).await;
}

#[tokio::test]
#[ignore]
async fn follows_a_folder_by_uid_ranges_without_condstore() {
    lifecycle(Mode::Ranges).await;
}

#[tokio::test]
#[ignore]
async fn a_new_uidvalidity_starts_the_folder_over() {
    servers!(env);
    let dir = TempDir::new().unwrap();
    let store = new_store(&dir);
    let mut conn = env.open().await;
    let name = unique("validity");
    create(&mut conn, &name).await;
    for i in 0..3 {
        conn.append_message(
            &name,
            &plain(
                &format!("m{i}"),
                &format!("v{i}@example.com"),
                "Mon, 02 Jan 2023 10:00:00 +0000",
            ),
            Flags::default(),
        )
        .await
        .unwrap();
    }
    sync_named(&mut conn, &store, &name, &Policy::default()).await;
    let f = folder_of(&store, &name);
    store
        .lock()
        .unwrap()
        .set_sync_state(
            f.id,
            &SyncState {
                uidvalidity: Some(f.sync.uidvalidity.unwrap() + 7),
                uidnext: f.sync.uidnext,
                highestmodseq: f.sync.highestmodseq,
                delta_link: None,
            },
        )
        .unwrap();
    let s = sync_named(&mut conn, &store, &name, &Policy::default()).await;
    assert_eq!(s.added, 3);
    let after = rows(&store, &f);
    assert_eq!(after.len(), 3);
    assert_eq!(
        folder_of(&store, &name).sync.uidvalidity,
        f.sync.uidvalidity
    );
}

#[tokio::test]
#[ignore]
async fn an_interrupted_first_download_picks_up_where_it_stopped() {
    servers!(env);
    let dir = TempDir::new().unwrap();
    let store = new_store(&dir);
    let mut conn = env.open().await;
    let name = unique("resume");
    create(&mut conn, &name).await;
    for i in 0..6 {
        conn.append_message(
            &name,
            &plain(
                &format!("m{i}"),
                &format!("r{i}@example.com"),
                "Mon, 02 Jan 2023 10:00:00 +0000",
            ),
            Flags::default(),
        )
        .await
        .unwrap();
    }
    sync_named(&mut conn, &store, &name, &Policy::default()).await;
    let f = folder_of(&store, &name);
    // As if the run stopped half way: two messages missing and the folder not marked done.
    let stored = rows(&store, &f);
    {
        let s = store.lock().unwrap();
        for m in stored.iter().take(2) {
            s.delete_message(m.id).unwrap();
        }
        s.set_sync_state(
            f.id,
            &SyncState {
                uidvalidity: f.sync.uidvalidity,
                ..Default::default()
            },
        )
        .unwrap();
    }
    let s = sync_named(&mut conn, &store, &name, &Policy::default()).await;
    assert_eq!(s.added, 2);
    let all = rows(&store, &f);
    assert_eq!(all.len(), 6);
    assert!(all.iter().all(|m| m.body_text.is_some()));
}

#[tokio::test]
#[ignore]
async fn a_complete_folder_with_headers_but_no_bodies_gets_its_bodies() {
    servers!(env);
    let dir = TempDir::new().unwrap();
    let store = new_store(&dir);
    let mut conn = env.open().await;
    let name = unique("headers-only");
    create(&mut conn, &name).await;
    for i in 0..3 {
        conn.append_message(
            &name,
            &plain(
                &format!("m{i}"),
                &format!("h{i}@example.com"),
                "Mon, 02 Jan 2023 10:00:00 +0000",
            ),
            Flags::default(),
        )
        .await
        .unwrap();
    }
    sync_named(&mut conn, &store, &name, &Policy::default()).await;
    let f = folder_of(&store, &name);
    assert!(f.sync.uidnext.is_some());
    // The folder is complete, and a later run stopped after storing headers of new mail.
    store.lock().unwrap().prune_bodies(i64::MAX).unwrap();
    assert!(rows(&store, &f).iter().all(|m| m.body_text.is_none()));
    sync_named(&mut conn, &store, &name, &Policy::default()).await;
    assert!(rows(&store, &f).iter().all(|m| m.body_text.is_some()));
}

#[tokio::test]
#[ignore]
async fn phones_keep_bodies_only_for_recent_mail() {
    servers!(env);
    let dir = TempDir::new().unwrap();
    let store = new_store(&dir);
    let mut conn = env.open().await;
    let name = unique("phone");
    create(&mut conn, &name).await;
    let recent = {
        let d = chrono_like(now() - 3600);
        plain("recent", "p1@example.com", &d)
    };
    let old = plain("old", "p2@example.com", "Wed, 01 Jan 2020 10:00:00 +0000");
    for m in [&recent, &old] {
        conn.append_message(&name, m, Flags::default())
            .await
            .unwrap();
    }
    let phone = Policy {
        body_days: Some(30),
    };
    sync_named(&mut conn, &store, &name, &phone).await;
    let all = rows(&store, &folder_of(&store, &name));
    let by = |s: &str| all.iter().find(|m| m.subject == s).unwrap();
    assert!(by("recent").body_text.is_some());
    assert!(by("old").body_text.is_none());

    // A computer's copy of the same folder has both; moving it to the phone policy drops the old one.
    let dir = TempDir::new().unwrap();
    let store = new_store(&dir);
    sync_named(&mut conn, &store, &name, &Policy::default()).await;
    let all = rows(&store, &folder_of(&store, &name));
    assert!(all.iter().all(|m| m.body_text.is_some()));
    sync_named(&mut conn, &store, &name, &phone).await;
    let all = rows(&store, &folder_of(&store, &name));
    let by = |s: &str| all.iter().find(|m| m.subject == s).unwrap();
    assert!(by("recent").body_text.is_some());
    assert!(by("old").body_text.is_none());
}

#[tokio::test]
#[ignore]
async fn an_account_never_holds_more_connections_than_its_limit() {
    servers!(env);
    let dir = TempDir::new().unwrap();
    let store = new_store(&dir);
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let imap = imap_for(&env, &store, tx);
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(imap.connect().await.unwrap());
    }
    let fourth = tokio::time::timeout(Duration::from_millis(300), imap.connect()).await;
    assert!(fourth.is_err(), "a fourth connection should wait");
    held.pop();
    let fourth = tokio::time::timeout(Duration::from_secs(5), imap.connect()).await;
    assert!(fourth.unwrap().is_ok());
}

// "Wed, 01 Jan 2020 10:00:00 +0000" for a unix time.
fn chrono_like(t: i64) -> String {
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    let wd = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][days.rem_euclid(7) as usize];
    let mon = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][m as usize - 1];
    format!(
        "{wd}, {d:02} {mon} {y} {:02}:{:02}:{:02} +0000",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

#[tokio::test]
#[ignore]
async fn actions_change_the_server_and_the_store() {
    servers!(env);
    let dir = TempDir::new().unwrap();
    let store = new_store(&dir);
    let mut conn = env.open().await;
    let (src, dst) = (unique("src"), unique("dst"));
    create(&mut conn, &src).await;
    create(&mut conn, &dst).await;
    let appended = conn
        .append_message(
            &src,
            &with_attachment("act", "act1@example.com"),
            Flags::default(),
        )
        .await
        .unwrap()
        .expect("APPENDUID");
    sync_named(&mut conn, &store, &src, &Policy::default()).await;
    sync_named(&mut conn, &store, &dst, &Policy::default()).await;
    let src_f = folder_of(&store, &src);
    let dst_f = folder_of(&store, &dst);
    let msg = rows(&store, &src_f).remove(0);
    assert_eq!(msg.uid, Some(appended.uid));

    // flags
    let flags = Flags {
        seen: true,
        flagged: true,
        ..Default::default()
    };
    conn.set_flags(&store, msg.id, flags).await.unwrap();
    assert_eq!(
        store
            .lock()
            .unwrap()
            .message(msg.id)
            .unwrap()
            .unwrap()
            .flags,
        flags
    );
    let mut check = env.open().await;
    let found = check
        .find_by_message_id(&src, "<act1@example.com>")
        .await
        .unwrap();
    assert_eq!(found, [appended.uid]);
    let reply = check
        .exec(&format!("UID FETCH {} (FLAGS)", appended.uid))
        .await
        .unwrap();
    assert_eq!(reply.fetched[0].flags, Some(flags));

    // attachment on demand, twice (the second comes from the store)
    let att = msg.attachments[0].id;
    assert_eq!(
        conn.download_attachment(&store, msg.id, att).await.unwrap(),
        PDF
    );
    assert!(
        store
            .lock()
            .unwrap()
            .message(msg.id)
            .unwrap()
            .unwrap()
            .attachments[0]
            .stored
    );
    assert_eq!(
        conn.download_attachment(&store, msg.id, att).await.unwrap(),
        PDF
    );

    // move, once with MOVE and once with COPY, \Deleted and UID EXPUNGE
    for use_move in [true, false] {
        conn.caps.move_ = use_move;
        let (from, to, from_f, to_f) = if use_move {
            (&src, &dst, src_f.id, dst_f.id)
        } else {
            (&dst, &src, dst_f.id, src_f.id)
        };
        let moved = conn
            .move_message(&store, msg.id, to_f, 1_700_000_000)
            .await
            .unwrap()
            .expect("COPYUID");
        let row = store.lock().unwrap().message(msg.id).unwrap().unwrap();
        assert_eq!((row.folder_id, row.uid), (to_f, Some(moved.uid)));
        assert_eq!(row.attachments.len(), 1);
        let undo = store.lock().unwrap().undo_entries(1_700_000_001).unwrap();
        let entry = undo.first().unwrap();
        assert_eq!(entry.kind, "imap-move");
        let u: crate::MoveUndo = serde_json::from_slice(&entry.payload).unwrap();
        assert_eq!(
            (
                u.message_id,
                u.from_folder,
                u.to_folder,
                u.to_uid,
                u.to_uidvalidity
            ),
            (msg.id, from_f, to_f, moved.uid, moved.uidvalidity)
        );
        assert!(check
            .find_by_message_id(from, "act1@example.com")
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            check
                .find_by_message_id(to, "act1@example.com")
                .await
                .unwrap(),
            [moved.uid]
        );
    }

    // delete
    conn.delete_message(&store, msg.id).await.unwrap();
    assert!(store.lock().unwrap().message(msg.id).unwrap().is_none());
    assert!(check
        .find_by_message_id(&src, "act1@example.com")
        .await
        .unwrap()
        .is_empty());
}

fn imap_for(
    env: &Env,
    store: &Arc<Mutex<Store>>,
    tx: tokio::sync::mpsc::UnboundedSender<Update>,
) -> Imap<StaticTokens> {
    let mut imap = Imap::new(
        Arc::new(Mutex::new(env.account())),
        Some(env.pass.clone()),
        Arc::new(StaticTokens::default()),
        store.clone(),
        Arc::new(Mutex::new(SignIn::default())),
        tx,
    )
    .unwrap()
    .with_tls(trust_anything());
    imap.server.transport = Transport::Plain;
    imap
}

async fn until(mut done: impl FnMut() -> bool) {
    for _ in 0..150 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out");
}

#[tokio::test]
#[ignore]
async fn the_first_download_does_the_inbox_first_and_reports_progress() {
    servers!(env);
    let dir = TempDir::new().unwrap();
    let store = new_store(&dir);
    let mut conn = env.open().await;
    conn.append_message(
        "INBOX",
        &plain(
            &unique("inbox"),
            &format!("{}@example.com", unique("i")),
            "Mon, 02 Jan 2023 10:00:00 +0000",
        ),
        Flags::default(),
    )
    .await
    .unwrap();
    create(&mut conn, &unique("zzz")).await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let imap = imap_for(&env, &store, tx);
    let total = imap.sync().await.unwrap();
    assert!(total.added >= 1);
    let mut synced = Vec::new();
    let mut progress = Vec::new();
    while let Ok(u) = rx.try_recv() {
        match u {
            Update::Synced { folder, .. } => synced.push(folder),
            Update::Progress(p) => progress.push(p),
            _ => {}
        }
    }
    assert_eq!(synced[0], "INBOX");
    let inbox: Vec<&Progress> = progress.iter().filter(|p| p.folder == "INBOX").collect();
    assert!(!inbox.is_empty());
    assert!(inbox.iter().any(|p| p.done == p.total && p.total >= 1));
    empty_inbox(&mut conn).await;
}

#[tokio::test]
#[ignore]
async fn idle_brings_in_new_mail_and_stops_on_request() {
    servers!(env);
    let dir = TempDir::new().unwrap();
    let store = new_store(&dir);
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let imap = Arc::new(imap_for(&env, &store, tx));
    let stop = Arc::new(Notify::new());
    let task = {
        let (imap, stop) = (imap.clone(), stop.clone());
        tokio::spawn(async move { imap.run(&stop).await })
    };
    let inbox_count = |store: &Arc<Mutex<Store>>| {
        let s = store.lock().unwrap();
        s.folders()
            .unwrap()
            .into_iter()
            .find(|f| f.name == "INBOX")
            .map(|f| s.folder_uids(f.id).unwrap().len())
            .unwrap_or(0)
    };
    until(|| {
        store
            .lock()
            .unwrap()
            .folders()
            .unwrap()
            .iter()
            .any(|f| f.name == "INBOX" && f.sync.uidnext.is_some())
    })
    .await;
    let before = inbox_count(&store);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut conn = env.open().await;
    let subject = unique("idle");
    conn.append_message(
        "INBOX",
        &plain(
            &subject,
            &format!("{subject}@example.com"),
            "Mon, 02 Jan 2023 10:00:00 +0000",
        ),
        Flags::default(),
    )
    .await
    .unwrap();
    until(|| inbox_count(&store) == before + 1).await;
    stop.notify_one();
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("run stops when asked")
        .unwrap();
    empty_inbox(&mut conn).await;
}

#[tokio::test]
#[ignore]
async fn a_refused_login_pauses_the_account_and_says_so_once() {
    servers!(env);
    let dir = TempDir::new().unwrap();
    let store = new_store(&dir);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut imap = imap_for(&env, &store, tx);
    imap.server.user = "nobody".into();
    let err = imap.sync().await.err().unwrap();
    assert!(matches!(err, Error::Auth(AuthFailure::Rejected)), "{err:?}");
    let err = imap.sync().await.err().unwrap();
    assert!(matches!(err, Error::Paused), "{err:?}");
    let mut events = 0;
    while let Ok(u) = rx.try_recv() {
        if let Update::SignIn(_) = u {
            events += 1;
        }
    }
    assert_eq!(events, 1);
}

async fn create(conn: &mut Connection, name: &str) {
    conn.create_folder(name).await.unwrap();
}

// The Inbox of the second test user is shared with other crates' tests, so what a test
// delivered there goes again.
async fn empty_inbox(conn: &mut Connection) {
    conn.select("INBOX").await.unwrap();
    conn.exec(r"STORE 1:* +FLAGS.SILENT (\Deleted)")
        .await
        .unwrap();
    conn.exec("EXPUNGE").await.unwrap();
}
