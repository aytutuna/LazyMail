use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use lazymail_accounts::{
    Account, AccountState, AuthFailure, Endpoint, Event, Login, Provider, Resource, Security,
    ServerSettings, SignIn, StaticTokens, TokenError,
};
use lazymail_smtp::{build, Address, Auth, Draft, Outbox, SendError, SentBox, Smtp};
use lazymail_store::{OutboxState, Store, StoreKey, TestWrapper};
use tempfile::TempDir;

#[derive(Default)]
struct FakeSent {
    known: Mutex<Vec<String>>,
    appended: Mutex<Vec<Vec<u8>>>,
    fail_search: bool,
    fail_append: Mutex<bool>,
}

impl SentBox for FakeSent {
    async fn contains(&self, message_id: &str) -> Result<bool, String> {
        if self.fail_search {
            return Err("connection lost".into());
        }
        Ok(self.known.lock().unwrap().iter().any(|m| m == message_id))
    }

    async fn append(&self, raw: &[u8]) -> Result<(), String> {
        if *self.fail_append.lock().unwrap() {
            return Err("mailbox busy".into());
        }
        self.appended.lock().unwrap().push(raw.to_vec());
        Ok(())
    }
}

fn store(dir: &TempDir) -> Store {
    Store::open(
        dir.path(),
        &StoreKey::generate(),
        Arc::new(TestWrapper::new()),
    )
    .unwrap()
}

fn account(id: &str, hostport: &str, security: Security, files_sent: bool) -> Account {
    let (host, port) = hostport.rsplit_once(':').unwrap();
    let mut a = Account::new(id, Provider::Other, &format!("{id}@example.test"), id);
    let ep = |host: &str, port: u16| Endpoint {
        host: host.into(),
        port,
        security,
        login: Login::LocalPart,
    };
    a.settings = Some(ServerSettings {
        imap: ep("127.0.0.1", 1),
        smtp: ep(host, port.parse().unwrap()),
        files_sent,
        gmail: false,
        max_connections: 2,
    });
    a
}

fn closed_port() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    format!("127.0.0.1:{}", l.local_addr().unwrap().port())
}

fn mail(from: &str, subject: &str) -> lazymail_smtp::Built {
    build(&Draft {
        from: Some(Address::new(from)),
        to: vec![Address::new("bob@example.test")],
        bcc: vec![Address::new("hidden@example.test")],
        subject: subject.into(),
        text: Some("hello".into()),
        date: 1_700_000_000,
        ..Draft::default()
    })
    .unwrap()
}

fn outbox<'a>(
    store: &'a Store,
    tokens: &'a StaticTokens,
    sent: &'a FakeSent,
    password: &str,
    cert: Option<Vec<u8>>,
) -> Outbox<'a, StaticTokens, FakeSent> {
    Outbox {
        store,
        tokens,
        sent_box: sent,
        auth: Auth::Password(password.into()),
        pinned_cert: cert,
    }
}

#[tokio::test]
async fn a_message_nobody_can_receive_is_parked() {
    let dir = TempDir::new().unwrap();
    let st = store(&dir);
    let mut acc = account("a", &closed_port(), Security::StartTls, false);
    let (tokens, sent) = (StaticTokens::default(), FakeSent::default());
    let id = st
        .outbox_enqueue(
            "<m1@example.test>",
            b"From: a@example.test\r\nSubject: s\r\n\r\nx\r\n",
            10,
        )
        .unwrap();

    let ob = outbox(&st, &tokens, &sent, "pw", None);
    let r = ob.run(&mut acc, &mut SignIn::default(), 10).await.unwrap();
    assert_eq!((r.sent, r.retry, r.failed), (0, 0, 1));
    let item = st.outbox_item(id).unwrap().unwrap();
    assert_eq!(item.state, OutboxState::Failed);
    assert!(item.last_error.unwrap().contains("bad message"));
}

#[tokio::test]
async fn an_unreachable_server_is_retried_with_growing_delays_then_given_up() {
    let dir = TempDir::new().unwrap();
    let st = store(&dir);
    let mut acc = account("a", &closed_port(), Security::StartTls, false);
    let (tokens, sent) = (StaticTokens::default(), FakeSent::default());
    let m = mail("a@example.test", "later");
    let id = st.outbox_enqueue(&m.message_id, &m.raw, 1000).unwrap();
    let ob = outbox(&st, &tokens, &sent, "pw", None);
    let mut signin = SignIn::default();

    let r = ob.run(&mut acc, &mut signin, 1000).await.unwrap();
    assert_eq!(r.retry, 1);
    let item = st.outbox_item(id).unwrap().unwrap();
    assert_eq!(
        (item.state, item.attempts, item.next_try),
        (OutboxState::Queued, 1, 1060)
    );
    // Not due yet.
    let r = ob.run(&mut acc, &mut signin, 1059).await.unwrap();
    assert_eq!(r.retry, 0);
    let r = ob.run(&mut acc, &mut signin, 1060).await.unwrap();
    assert_eq!(r.retry, 1);
    let item = st.outbox_item(id).unwrap().unwrap();
    assert_eq!((item.attempts, item.next_try), (2, 1060 + 120));
    // A network failure says nothing about the sign-in.
    assert_eq!(signin.state("a"), AccountState::SignedIn);

    let r = ob
        .run(&mut acc, &mut signin, 1000 + 4 * 86400)
        .await
        .unwrap();
    assert_eq!(r.failed, 1);
    let item = st.outbox_item(id).unwrap().unwrap();
    assert_eq!(item.state, OutboxState::Failed);
    assert!(item.last_error.unwrap().starts_with("gave up"));
}

#[tokio::test]
async fn scheduled_mail_already_in_sent_is_not_sent_again() {
    let dir = TempDir::new().unwrap();
    let st = store(&dir);
    // A send would be refused: nothing listens here.
    let mut acc = account("a", &closed_port(), Security::StartTls, false);
    let (tokens, sent) = (StaticTokens::default(), FakeSent::default());
    let m = mail("a@example.test", "scheduled");
    let id = st.outbox_enqueue(&m.message_id, &m.raw, 1000).unwrap();
    st.outbox_requeue(id, 5000).unwrap();
    sent.known.lock().unwrap().push(m.message_id.clone());

    let ob = outbox(&st, &tokens, &sent, "pw", None);
    let r = ob
        .run(&mut acc, &mut SignIn::default(), 5000)
        .await
        .unwrap();
    assert_eq!((r.sent, r.retry, r.failed), (1, 0, 0));
    assert!(st.outbox_list().unwrap().is_empty());
    assert!(sent.appended.lock().unwrap().is_empty());
}

#[tokio::test]
async fn mail_waits_when_sent_cannot_be_searched() {
    let dir = TempDir::new().unwrap();
    let st = store(&dir);
    let mut acc = account("a", &closed_port(), Security::StartTls, false);
    let tokens = StaticTokens::default();
    let sent = FakeSent {
        fail_search: true,
        ..FakeSent::default()
    };
    let m = mail("a@example.test", "scheduled");
    let id = st.outbox_enqueue(&m.message_id, &m.raw, 1000).unwrap();
    st.outbox_requeue(id, 5000).unwrap();

    let ob = outbox(&st, &tokens, &sent, "pw", None);
    let r = ob
        .run(&mut acc, &mut SignIn::default(), 5000)
        .await
        .unwrap();
    assert_eq!((r.sent, r.retry), (0, 1));
    let item = st.outbox_item(id).unwrap().unwrap();
    assert_eq!(item.state, OutboxState::Queued);
    assert_eq!(item.next_try, 5060);
    assert!(item.last_error.unwrap().contains("could not search Sent"));
}

#[tokio::test]
async fn oauth_asks_the_token_source_and_needs_sign_in_without_one() {
    let acc = account("a", &closed_port(), Security::StartTls, false);
    let tokens = StaticTokens::default();
    let err = Smtp::new(&acc, &Auth::OAuth, &tokens, None).await.err();
    assert_eq!(err, Some(SendError::Auth(AuthFailure::SignInExpired)));

    tokens.set(
        "a",
        Resource::Mail,
        Err(TokenError::Failed("offline".into())),
    );
    let err = Smtp::new(&acc, &Auth::OAuth, &tokens, None).await.err();
    assert!(matches!(err, Some(SendError::Temporary(_))));

    tokens.set("a", Resource::Mail, Ok("tok".into()));
    assert!(Smtp::new(&acc, &Auth::OAuth, &tokens, None).await.is_ok());
}

#[tokio::test]
async fn graph_accounts_have_no_smtp() {
    let mut acc = account("a", &closed_port(), Security::StartTls, false);
    acc.mail = lazymail_accounts::MailAccess::Graph;
    let err = Smtp::new(
        &acc,
        &Auth::Password("x".into()),
        &StaticTokens::default(),
        None,
    )
    .await
    .err();
    assert!(matches!(err, Some(SendError::Permanent(_))));
}

mod sink {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    struct Sink {
        addr: String,
        tls_addr: String,
        dir: std::path::PathBuf,
        cert: Vec<u8>,
        user: String,
        pass: String,
    }

    fn sink() -> Option<Sink> {
        let var = |n: &str| std::env::var(n).ok();
        let dir = std::path::PathBuf::from(var("LAZYMAIL_TEST_SMTP_DIR")?);
        // start.sh puts the certificate next to the sink's mail directory.
        let pem = std::fs::read_to_string(dir.parent()?.join("cert.pem")).ok()?;
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        Some(Sink {
            addr: var("LAZYMAIL_TEST_SMTP")?,
            tls_addr: var("LAZYMAIL_TEST_SMTPS")?,
            dir,
            cert: STANDARD.decode(b64).ok()?,
            user: var("LAZYMAIL_TEST_USER")?,
            pass: var("LAZYMAIL_TEST_PASS")?,
        })
    }

    impl Sink {
        fn files(&self) -> Vec<String> {
            let mut names: Vec<_> = std::fs::read_dir(&self.dir)
                .unwrap()
                .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
                .collect();
            names.sort();
            names
        }

        fn with_id(&self, message_id: &str) -> Vec<String> {
            self.files()
                .into_iter()
                .filter(|f| f.contains(&format!("Message-ID: {message_id}\r\n")))
                .collect()
        }

        fn account(&self, security: Security, files_sent: bool) -> Account {
            let hostport = match security {
                Security::StartTls => &self.addr,
                Security::Tls => &self.tls_addr,
            };
            account(&self.user, hostport, security, files_sent)
        }
    }

    #[tokio::test]
    #[ignore]
    async fn password_over_starttls_delivers_to_every_recipient_without_bcc() {
        let Some(s) = sink() else { return };
        let acc = s.account(Security::StartTls, false);
        let m = mail(&acc.address, "starttls");
        let smtp = Smtp::new(
            &acc,
            &Auth::Password(s.pass.clone()),
            &StaticTokens::default(),
            Some(&s.cert),
        )
        .await
        .unwrap();
        smtp.send(&m.raw).await.unwrap();

        let got = s.with_id(&m.message_id);
        assert_eq!(got.len(), 1);
        let f = &got[0];
        assert!(
            f.contains(&format!("X-Sink-From: <{}>", acc.address)),
            "{f}"
        );
        assert!(
            f.contains("X-Sink-To: <bob@example.test> <hidden@example.test>"),
            "{f}"
        );
        assert!(f.contains("X-Sink-Auth: yes"));
        assert!(!f.contains("Bcc:"), "{f}");
        assert!(f.contains("\r\nhello"));
    }

    #[tokio::test]
    #[ignore]
    async fn implicit_tls_delivers() {
        let Some(s) = sink() else { return };
        let acc = s.account(Security::Tls, false);
        let m = mail(&acc.address, "implicit");
        let smtp = Smtp::new(
            &acc,
            &Auth::Password(s.pass.clone()),
            &StaticTokens::default(),
            Some(&s.cert),
        )
        .await
        .unwrap();
        smtp.send(&m.raw).await.unwrap();
        assert_eq!(s.with_id(&m.message_id).len(), 1);
    }

    #[tokio::test]
    #[ignore]
    async fn an_untrusted_certificate_is_not_accepted() {
        let Some(s) = sink() else { return };
        let acc = s.account(Security::StartTls, false);
        let m = mail(&acc.address, "untrusted");
        let smtp = Smtp::new(
            &acc,
            &Auth::Password(s.pass.clone()),
            &StaticTokens::default(),
            None,
        )
        .await
        .unwrap();
        assert!(smtp.send(&m.raw).await.is_err());
        assert!(s.with_id(&m.message_id).is_empty());
    }

    #[tokio::test]
    #[ignore]
    async fn a_wrong_password_is_an_auth_failure() {
        let Some(s) = sink() else { return };
        let acc = s.account(Security::StartTls, false);
        let m = mail(&acc.address, "badpw");
        let smtp = Smtp::new(
            &acc,
            &Auth::Password("nope".into()),
            &StaticTokens::default(),
            Some(&s.cert),
        )
        .await
        .unwrap();
        let e = smtp.send(&m.raw).await.unwrap_err();
        assert_eq!(e, SendError::Auth(AuthFailure::Rejected));
        assert!(s.with_id(&m.message_id).is_empty());
    }

    #[tokio::test]
    #[ignore]
    async fn the_outbox_sends_then_files_the_copy() {
        let Some(s) = sink() else { return };
        let dir = TempDir::new().unwrap();
        let st = store(&dir);
        let mut acc = s.account(Security::StartTls, false);
        let (tokens, sent) = (StaticTokens::default(), FakeSent::default());
        let m = mail(&acc.address, "outbox");
        st.outbox_enqueue(&m.message_id, &m.raw, 100).unwrap();

        let ob = outbox(&st, &tokens, &sent, &s.pass, Some(s.cert.clone()));
        let r = ob.run(&mut acc, &mut SignIn::default(), 100).await.unwrap();
        assert_eq!((r.sent, r.copies_pending), (1, 0));
        assert_eq!(s.with_id(&m.message_id).len(), 1);
        assert!(st.outbox_list().unwrap().is_empty());
        let copies = sent.appended.lock().unwrap();
        assert_eq!(copies.len(), 1);
        // The copy keeps the Bcc header.
        assert!(String::from_utf8_lossy(&copies[0]).contains("Bcc:"));
    }

    #[tokio::test]
    #[ignore]
    async fn providers_that_file_sent_mail_get_no_copy() {
        let Some(s) = sink() else { return };
        let dir = TempDir::new().unwrap();
        let st = store(&dir);
        let mut acc = s.account(Security::StartTls, true);
        let (tokens, sent) = (StaticTokens::default(), FakeSent::default());
        let m = mail(&acc.address, "files-itself");
        st.outbox_enqueue(&m.message_id, &m.raw, 100).unwrap();

        let ob = outbox(&st, &tokens, &sent, &s.pass, Some(s.cert.clone()));
        ob.run(&mut acc, &mut SignIn::default(), 100).await.unwrap();
        assert_eq!(s.with_id(&m.message_id).len(), 1);
        assert!(st.outbox_list().unwrap().is_empty());
        assert!(sent.appended.lock().unwrap().is_empty());
    }

    #[tokio::test]
    #[ignore]
    async fn a_copy_that_fails_is_retried_and_the_mail_is_not_sent_twice() {
        let Some(s) = sink() else { return };
        let dir = TempDir::new().unwrap();
        let st = store(&dir);
        let mut acc = s.account(Security::StartTls, false);
        let tokens = StaticTokens::default();
        let sent = FakeSent::default();
        *sent.fail_append.lock().unwrap() = true;
        let m = mail(&acc.address, "copy-later");
        let id = st.outbox_enqueue(&m.message_id, &m.raw, 100).unwrap();

        let ob = outbox(&st, &tokens, &sent, &s.pass, Some(s.cert.clone()));
        let mut signin = SignIn::default();
        let r = ob.run(&mut acc, &mut signin, 100).await.unwrap();
        assert_eq!((r.sent, r.copies_pending), (1, 1));
        assert_eq!(
            st.outbox_item(id).unwrap().unwrap().state,
            OutboxState::Sent
        );

        *sent.fail_append.lock().unwrap() = false;
        let r = ob.run(&mut acc, &mut signin, 200).await.unwrap();
        assert_eq!((r.sent, r.copies_pending), (0, 0));
        assert!(st.outbox_list().unwrap().is_empty());
        assert_eq!(sent.appended.lock().unwrap().len(), 1);
        assert_eq!(s.with_id(&m.message_id).len(), 1);
    }

    #[tokio::test]
    #[ignore]
    async fn a_refused_sign_in_pauses_only_that_account_and_keeps_the_mail() {
        let Some(s) = sink() else { return };
        let (tokens, sent) = (StaticTokens::default(), FakeSent::default());
        let mut signin = SignIn::default();

        let dir_a = TempDir::new().unwrap();
        let st_a = store(&dir_a);
        let mut a = s.account(Security::StartTls, false);
        a.id = "a".into();
        let m = mail(&a.address, "paused");
        let id = st_a.outbox_enqueue(&m.message_id, &m.raw, 100).unwrap();
        let bad = outbox(&st_a, &tokens, &sent, "nope", Some(s.cert.clone()));

        let r = bad.run(&mut a, &mut signin, 100).await.unwrap();
        assert_eq!(
            r.events,
            vec![Event::NeedsSignIn {
                account_id: "a".into(),
                reason: AuthFailure::Rejected
            }]
        );
        let item = st_a.outbox_item(id).unwrap().unwrap();
        assert_eq!((item.state, item.attempts), (OutboxState::Queued, 1));
        assert!(signin.work_paused("a"));

        // Within the hour nothing is tried, so no second notice and no second attempt.
        let r = bad.run(&mut a, &mut signin, 200).await.unwrap();
        assert!(r.events.is_empty());
        assert_eq!(st_a.outbox_item(id).unwrap().unwrap().attempts, 1);

        // Another account carries on.
        let dir_b = TempDir::new().unwrap();
        let st_b = store(&dir_b);
        let mut b = s.account(Security::StartTls, false);
        b.id = "b".into();
        let mb = mail(&b.address, "other-account");
        st_b.outbox_enqueue(&mb.message_id, &mb.raw, 100).unwrap();
        let good_b = outbox(&st_b, &tokens, &sent, &s.pass, Some(s.cert.clone()));
        let r = good_b.run(&mut b, &mut signin, 300).await.unwrap();
        assert_eq!(r.sent, 1);
        assert!(s.with_id(&m.message_id).is_empty());

        // After the new password the hourly retry sends the waiting mail.
        let good_a = outbox(&st_a, &tokens, &sent, &s.pass, Some(s.cert.clone()));
        let r = good_a.run(&mut a, &mut signin, 100 + 3600).await.unwrap();
        assert_eq!(r.sent, 1);
        assert_eq!(s.with_id(&m.message_id).len(), 1);
        assert!(!signin.work_paused("a"));
    }
}
