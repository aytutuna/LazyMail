//! Servers that cannot be run here (Gmail, Outlook.com, a server from before MOVE and UIDPLUS),
//! played from scripts written from their public documentation, not recorded from accounts.

use std::sync::{Arc, Mutex};

use lazymail_accounts::{
    xoauth2_base64, Account, AuthFailure, Event, MailAccess, Provider, Resource, SignIn,
    StaticTokens,
};
use lazymail_store::{Flags, NewMessage, Store, StoreKey, TestWrapper};
use lazymail_testserver::{ReplayServer, Transcript};
use tempfile::TempDir;

use super::{rows, sync_named, trust_anything};
use crate::conn::{Connection, Credential, Server, Transport};
use crate::folders;
use crate::{Error, Imap, Policy, Update};

fn serve(script: &str) -> ReplayServer {
    ReplayServer::start(Transcript::parse(script).unwrap()).unwrap()
}

fn server_of(replay: &ReplayServer, provider: Provider, gmail: bool) -> Server {
    Server {
        host: "127.0.0.1".into(),
        port: replay.addr().port(),
        transport: Transport::Plain,
        user: "u".into(),
        provider,
        gmail,
    }
}

async fn open(replay: &ReplayServer, provider: Provider, gmail: bool) -> crate::Result<Connection> {
    Connection::open(
        &server_of(replay, provider, gmail),
        &Credential::Password("pw".into()),
        &trust_anything(),
        true,
    )
    .await
}

fn store() -> (TempDir, Arc<Mutex<Store>>) {
    let dir = TempDir::new().unwrap();
    let s = Store::open(
        dir.path(),
        &StoreKey::generate(),
        Arc::new(TestWrapper::new()),
    )
    .unwrap();
    (dir, Arc::new(Mutex::new(s)))
}

const GMAIL_CAPS: &str = "IMAP4rev1 UNSELECT IDLE NAMESPACE ID CHILDREN X-GM-EXT-1 UIDPLUS \
                          ENABLE MOVE CONDSTORE ESEARCH LIST-EXTENDED SPECIAL-USE";

fn login(caps: &str) -> String {
    format!(
        "S: * OK server ready\n\
         C: <tag> LOGIN \"u\" \"pw\"\n\
         S: <tag> OK [CAPABILITY {caps}] u authenticated (Success)\n\
         C: <tag> CAPABILITY\n\
         S: * CAPABILITY {caps}\n\
         S: <tag> OK Success\n"
    )
}

// A literal as transcript lines: the length goes in the prefix, the text follows line by line.
fn literal(text: &str) -> (usize, String) {
    let body = text.replace('\n', "\r\n");
    let inner = text.strip_suffix('\n').unwrap_or(text);
    let lines: Vec<String> = inner.split('\n').map(|l| format!("S: {l}")).collect();
    (body.len(), lines.join("\n"))
}

const HEADER: &str = "From: Ann <ann@example.com>\nTo: bob@example.org\nSubject: Receipt\n\
                      Date: Tue, 03 Jan 2023 10:00:00 +0000\nMessage-ID: <g1@example.com>\n\n";
const TEXT_STRUCTURE: &str =
    "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 10 1 NIL NIL NIL)";

// "* n FETCH (UID u FLAGS (..) ... BODY[HEADER] {n}" and the rest of the reply for one message.
fn header_fetch(seq: u32, uid: u32, flags: &str, tail: &str) -> String {
    let (n, lit) = literal(HEADER);
    format!(
        "S: * {seq} FETCH (UID {uid} FLAGS ({flags}) RFC822.SIZE 321 \
         INTERNALDATE \"03-Jan-2023 10:00:00 +0000\" BODY[HEADER] {{{n}}}\n{lit}\n\
         S:  BODYSTRUCTURE {TEXT_STRUCTURE} {tail})"
    )
}

fn body_fetch(seq: u32, uid: u32) -> String {
    let (hn, header) = literal(HEADER);
    let (mn, mime) = literal("Content-Type: text/plain; charset=utf-8\n\n");
    format!(
        "S: * {seq} FETCH (UID {uid} BODY[1.MIME] {{{mn}}}\n{mime}\n\
         S:  BODY[1] {{11}}\nS: hello box\nS:  BODY[HEADER] {{{hn}}}\n{header}\nS: )"
    )
}

fn select(name: &str, validity: u32, exists: u32, uidnext: u32, modseq: u32) -> String {
    format!(
        "C: <tag> SELECT \"{name}\" (CONDSTORE)\n\
         S: * {exists} EXISTS\n\
         S: * OK [UIDVALIDITY {validity}] UIDs valid.\n\
         S: * OK [UIDNEXT {uidnext}] Predicted next UID.\n\
         S: * OK [HIGHESTMODSEQ {modseq}] Highest\n\
         S: <tag> OK [READ-WRITE] {name} selected. (Success)\n"
    )
}

const HEADER_FETCH_ITEMS: &str =
    "(UID FLAGS RFC822.SIZE INTERNALDATE BODY.PEEK[HEADER] BODYSTRUCTURE X-GM-MSGID X-GM-LABELS)";

#[tokio::test]
async fn gmail_keeps_all_mail_spam_and_trash_only() {
    let script = format!(
        "{}C: <tag> LIST \"\" \"*\"\n\
         S: * LIST (\\HasNoChildren) \"/\" \"INBOX\"\n\
         S: * LIST (\\HasNoChildren \\Important) \"/\" \"[Gmail]/Important\"\n\
         S: * LIST (\\HasNoChildren \\Sent) \"/\" \"[Gmail]/Sent Mail\"\n\
         S: * LIST (\\HasNoChildren \\Drafts) \"/\" \"[Gmail]/Drafts\"\n\
         S: * LIST (\\HasNoChildren \\Trash) \"/\" \"[Gmail]/Trash\"\n\
         S: * LIST (\\HasNoChildren \\Junk) \"/\" \"[Gmail]/Spam\"\n\
         S: * LIST (\\HasNoChildren) \"/\" \"Receipts\"\n\
         S: * LIST (\\HasChildren \\Noselect) \"/\" \"[Gmail]\"\n\
         S: * LIST (\\HasNoChildren \\All) \"/\" \"[Gmail]/All Mail\"\n\
         S: <tag> OK Success\n",
        login(GMAIL_CAPS)
    );
    let replay = serve(&script);
    let mut conn = open(&replay, Provider::Gmail, true).await.unwrap();
    let (_dir, store) = store();
    let kept = folders::refresh(&mut conn, &store).await.unwrap();
    let names: Vec<(&str, Option<&str>)> = kept
        .iter()
        .map(|f| (f.name.as_str(), f.role.as_deref()))
        .collect();
    assert_eq!(
        names,
        [
            ("[Gmail]/All Mail", Some("all")),
            ("[Gmail]/Spam", Some("junk")),
            ("[Gmail]/Trash", Some("trash")),
        ]
    );
    drop(conn);
    replay.finish().unwrap();
}

fn all_mail_script(extra: &str) -> String {
    all_mail_script_with(extra, "", "")
}

// `before` goes ahead of the header reply and `after` behind the body reply, as the server
// would send them when another client changes flags meanwhile.
fn all_mail_script_with(extra: &str, before: &str, after: &str) -> String {
    let labels = r#"X-GM-MSGID 1750000000000000011 X-GM-LABELS ("\\Inbox" Receipts "&AOQ-ssig")"#;
    format!(
        "{}{}C: <tag> UID SEARCH ALL\n\
         S: * SEARCH 1\n\
         S: <tag> OK Success\n\
         C: <tag> UID FETCH 1 {HEADER_FETCH_ITEMS}\n\
         {before}{}\n\
         S: <tag> OK Success\n\
         C: <tag> UID FETCH 1 (BODY.PEEK[1.MIME] BODY.PEEK[1] BODY.PEEK[HEADER])\n\
         {}\n{after}\
         S: <tag> OK Success\n{extra}",
        login(GMAIL_CAPS),
        select("[Gmail]/All Mail", 5, 1, 2, 1873),
        header_fetch(1, 1, "\\Seen", labels),
        body_fetch(1, 1),
    )
}

#[tokio::test]
async fn gmail_rows_are_keyed_by_msgid_with_their_labels() {
    let replay = serve(&all_mail_script(""));
    let mut conn = open(&replay, Provider::Gmail, true).await.unwrap();
    let (_dir, store) = store();
    let s = sync_named(&mut conn, &store, "[Gmail]/All Mail", &Policy::default()).await;
    assert_eq!(s.added, 1);
    let f = store.lock().unwrap().folders().unwrap().remove(0);
    let m = rows(&store, &f).remove(0);
    assert_eq!(m.gm_msgid, Some(1_750_000_000_000_000_011));
    assert_eq!(m.labels.len(), 3);
    for l in ["\\Inbox", "Receipts", "ässig"] {
        assert!(m.labels.iter().any(|x| x == l), "{l} in {:?}", m.labels);
    }
    assert!(m.flags.seen);
    assert_eq!(m.body_text.as_deref().map(str::trim_end), Some("hello box"));
    assert_eq!(f.sync.highestmodseq, Some(1873));
    assert_eq!(f.sync.uidnext, Some(2));
    drop(conn);
    replay.finish().unwrap();
}

#[tokio::test]
async fn flag_updates_that_arrive_mid_command_are_not_taken_for_answers() {
    // Another client marks UID 7 read while the headers load, and UID 1 while its body loads.
    let script = all_mail_script_with(
        "",
        "S: * 3 FETCH (UID 7 FLAGS (\\Seen))\n",
        "S: * 1 FETCH (UID 1 FLAGS (\\Seen \\Flagged))\n",
    );
    let replay = serve(&script);
    let mut conn = open(&replay, Provider::Gmail, true).await.unwrap();
    let (_dir, store) = store();
    let s = sync_named(&mut conn, &store, "[Gmail]/All Mail", &Policy::default()).await;
    assert_eq!(s.added, 1);
    let f = store.lock().unwrap().folders().unwrap().remove(0);
    let all = rows(&store, &f);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].subject, "Receipt");
    assert_eq!(all[0].body_text.as_deref().map(str::trim_end), Some("hello box"));
    drop(conn);
    replay.finish().unwrap();
}

#[tokio::test]
async fn a_message_that_moves_folder_keeps_its_row() {
    // The same X-GM-MSGID turns up in Trash with its own UID.
    let trash = format!(
        "{}C: <tag> UID SEARCH ALL\nS: * SEARCH 4\nS: <tag> OK Success\n\
         C: <tag> UID FETCH 4 {HEADER_FETCH_ITEMS}\n{}\nS: <tag> OK Success\n",
        select("[Gmail]/Trash", 8, 1, 5, 99),
        header_fetch(
            1,
            4,
            "\\Seen \\Deleted",
            r#"X-GM-MSGID 1750000000000000011 X-GM-LABELS ("\\Trash")"#
        ),
    );
    let replay = serve(&all_mail_script(&trash));
    let mut conn = open(&replay, Provider::Gmail, true).await.unwrap();
    let (_dir, store) = store();
    sync_named(&mut conn, &store, "[Gmail]/All Mail", &Policy::default()).await;
    let id = store
        .lock()
        .unwrap()
        .find_by_gm_msgid(1_750_000_000_000_000_011)
        .unwrap()
        .unwrap();
    sync_named(&mut conn, &store, "[Gmail]/Trash", &Policy::default()).await;
    let s = store.lock().unwrap();
    assert_eq!(
        s.find_by_gm_msgid(1_750_000_000_000_000_011).unwrap(),
        Some(id)
    );
    let m = s.message(id).unwrap().unwrap();
    let trash = s
        .folders()
        .unwrap()
        .into_iter()
        .find(|f| f.name == "[Gmail]/Trash")
        .unwrap();
    assert_eq!((m.folder_id, m.uid), (trash.id, Some(4)));
    assert_eq!(m.labels, ["\\Trash"]);
    assert!(m.flags.deleted);
    drop(s);
    drop(conn);
    replay.finish().unwrap();
}

// All Mail looked at again after the message left it (deleted in the web app, say).
fn all_mail_emptied() -> String {
    format!(
        "{}C: <tag> UID FETCH 1:* (FLAGS X-GM-LABELS) (CHANGEDSINCE 1873)\n\
         S: <tag> OK Success\n\
         C: <tag> UID SEARCH UID 2:*\n\
         S: * SEARCH\n\
         S: <tag> OK Success\n\
         C: <tag> UID SEARCH ALL\n\
         S: * SEARCH\n\
         S: <tag> OK Success\n",
        select("[Gmail]/All Mail", 5, 0, 2, 1900)
    )
}

#[tokio::test]
async fn a_message_deleted_elsewhere_keeps_its_row_when_trash_is_synced_after_all_mail() {
    let trash = format!(
        "{}{}C: <tag> UID SEARCH ALL\nS: * SEARCH 4\nS: <tag> OK Success\n\
         C: <tag> UID FETCH 4 {HEADER_FETCH_ITEMS}\n{}\nS: <tag> OK Success\n",
        all_mail_emptied(),
        select("[Gmail]/Trash", 8, 1, 5, 99),
        header_fetch(
            1,
            4,
            "\\Seen",
            r#"X-GM-MSGID 1750000000000000011 X-GM-LABELS ("\\Trash")"#
        ),
    );
    let replay = serve(&all_mail_script(&trash));
    let mut conn = open(&replay, Provider::Gmail, true).await.unwrap();
    let (_dir, store) = store();
    sync_named(&mut conn, &store, "[Gmail]/All Mail", &Policy::default()).await;
    let id = store
        .lock()
        .unwrap()
        .find_by_gm_msgid(1_750_000_000_000_000_011)
        .unwrap()
        .unwrap();
    sync_named(&mut conn, &store, "[Gmail]/All Mail", &Policy::default()).await;
    sync_named(&mut conn, &store, "[Gmail]/Trash", &Policy::default()).await;
    assert_eq!(crate::sync::drop_unplaced(&store).unwrap(), 0);
    let s = store.lock().unwrap();
    let m = s.message(id).unwrap().unwrap();
    assert_eq!(m.uid, Some(4));
    assert_eq!(m.labels, ["\\Trash"]);
    drop(s);
    drop(conn);
    replay.finish().unwrap();
}

#[tokio::test]
async fn a_gmail_message_found_in_no_folder_is_dropped_at_the_end() {
    let replay = serve(&all_mail_script(&all_mail_emptied()));
    let mut conn = open(&replay, Provider::Gmail, true).await.unwrap();
    let (_dir, store) = store();
    sync_named(&mut conn, &store, "[Gmail]/All Mail", &Policy::default()).await;
    sync_named(&mut conn, &store, "[Gmail]/All Mail", &Policy::default()).await;
    let gm = 1_750_000_000_000_000_011;
    assert!(store.lock().unwrap().find_by_gm_msgid(gm).unwrap().is_some());
    assert_eq!(crate::sync::drop_unplaced(&store).unwrap(), 1);
    assert!(store.lock().unwrap().find_by_gm_msgid(gm).unwrap().is_none());
    drop(conn);
    replay.finish().unwrap();
}

#[tokio::test]
async fn gmails_download_limit_ends_the_sync_with_its_own_error() {
    let script = format!(
        "{}{}C: <tag> UID SEARCH ALL\nS: * SEARCH 1\nS: <tag> OK Success\n\
         C: <tag> UID FETCH 1 {HEADER_FETCH_ITEMS}\n\
         S: * BYE [ALERT] Account exceeded command or bandwidth limits. (Failure)\n",
        login(GMAIL_CAPS),
        select("[Gmail]/All Mail", 5, 1, 2, 1873),
    );
    let replay = serve(&script);
    let mut conn = open(&replay, Provider::Gmail, true).await.unwrap();
    let (_dir, store) = store();
    let folder = store
        .lock()
        .unwrap()
        .upsert_folder("[Gmail]/All Mail", None)
        .unwrap();
    let err = crate::sync::sync_folder(
        &mut conn,
        &store,
        &folder,
        &Policy::default(),
        0,
        &mut |_| {},
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(err, Error::DownloadLimit), "{err:?}");
    // Nothing is marked done, so the next day's run starts from what is stored.
    let state = store
        .lock()
        .unwrap()
        .folder(folder.id)
        .unwrap()
        .unwrap()
        .sync;
    assert_eq!(state.uidnext, None);
    drop(conn);
    replay.finish().unwrap();
}

type Rig = (
    Imap<StaticTokens>,
    Arc<Mutex<Account>>,
    tokio::sync::mpsc::UnboundedReceiver<Update>,
    Arc<Mutex<SignIn>>,
    TempDir,
);

fn outlook_imap(replay: &ReplayServer, tokens: StaticTokens) -> Rig {
    let account = Arc::new(Mutex::new(Account::new(
        "o1",
        Provider::Microsoft365,
        "u@contoso.example",
        "U",
    )));
    let (dir, store) = store();
    let signin = Arc::new(Mutex::new(SignIn::default()));
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mut imap = Imap::new(
        account.clone(),
        None,
        Arc::new(tokens),
        store,
        signin.clone(),
        tx,
    )
    .unwrap()
    .with_tls(trust_anything())
    .verified();
    imap.server = Server {
        user: "u@contoso.example".into(),
        ..server_of(replay, Provider::Microsoft365, false)
    };
    (imap, account, rx, signin, dir)
}

fn xoauth_script(reply: &str) -> String {
    format!(
        "S: * OK The Microsoft Exchange IMAP4 service is ready.\n\
         C: <tag> AUTHENTICATE XOAUTH2\n\
         S: +\n\
         C: {}\n\
         S: <tag> NO {reply}\n",
        xoauth2_base64("u@contoso.example", "access-1")
    )
}

#[tokio::test]
async fn outlook_with_imap_switched_off_moves_the_account_to_graph() {
    let replay = serve(&xoauth_script("User is authenticated but not connected."));
    let tokens = StaticTokens::default();
    tokens.set("o1", Resource::Mail, Ok("access-1".into()));
    let (imap, account, mut rx, signin, _dir) = outlook_imap(&replay, tokens);
    let err = imap.connect().await.err().unwrap();
    assert!(
        matches!(err, Error::Auth(AuthFailure::GraphNeeded)),
        "{err:?}"
    );
    assert_eq!(account.lock().unwrap().mail, MailAccess::Graph);
    assert!(!signin.lock().unwrap().work_paused("o1"));
    match rx.try_recv().unwrap() {
        Update::SignIn(Event::UsesGraph { account_id }) => assert_eq!(account_id, "o1"),
        other => panic!("{other:?}"),
    }
    replay.finish().unwrap();
}

#[tokio::test]
async fn an_expired_microsoft_sign_in_needs_a_new_one_without_asking_the_server() {
    // No token to send: the server is never contacted.
    let replay = serve("S: * OK never used\n");
    let (imap, _account, mut rx, signin, _dir) = outlook_imap(&replay, StaticTokens::default());
    let err = imap.connect().await.err().unwrap();
    assert!(
        matches!(err, Error::Auth(AuthFailure::SignInExpired)),
        "{err:?}"
    );
    assert!(signin.lock().unwrap().work_paused("o1"));
    assert!(matches!(
        rx.try_recv().unwrap(),
        Update::SignIn(Event::NeedsSignIn {
            reason: AuthFailure::SignInExpired,
            ..
        })
    ));
    drop(replay);
}

#[tokio::test]
async fn a_rejected_token_is_a_sign_in_problem_of_the_account() {
    let replay = serve(&xoauth_script("AUTHENTICATE failed."));
    let tokens = StaticTokens::default();
    tokens.set("o1", Resource::Mail, Ok("access-1".into()));
    let (imap, _account, _rx, signin, _dir) = outlook_imap(&replay, tokens);
    let err = imap.connect().await.err().unwrap();
    assert!(matches!(err, Error::Auth(AuthFailure::Rejected)), "{err:?}");
    assert!(signin.lock().unwrap().work_paused("o1"));
    replay.finish().unwrap();
}

fn old_server(then: &str) -> String {
    format!(
        "{}C: <tag> SELECT \"INBOX\"\n\
         S: * 3 EXISTS\n\
         S: * OK [UIDVALIDITY 14] UIDVALIDITY value\n\
         S: * OK [UIDNEXT 40] The next unique identifier value\n\
         S: <tag> OK [READ-WRITE] SELECT completed.\n{then}",
        login("IMAP4rev1")
    )
}

fn with_message(store: &Arc<Mutex<Store>>, uid: u32) -> (i64, i64) {
    let s = store.lock().unwrap();
    let inbox = s.upsert_folder("INBOX", Some("inbox")).unwrap();
    let archive = s.upsert_folder("Archive", Some("archive")).unwrap();
    let id = s
        .insert_message(&NewMessage {
            folder_id: inbox.id,
            uid: Some(uid),
            subject: "old".into(),
            message_id: Some("g1@example.com".into()),
            body_text: Some("hello box".into()),
            flags: Flags::default(),
            ..Default::default()
        })
        .unwrap();
    (id, archive.id)
}

#[tokio::test]
async fn a_server_without_move_or_uidplus_copies_then_expunges() {
    // Such a server says nothing about the new UID, so the row waits in the new folder until
    // that folder is synced and shows the same Message-ID.
    let archive_sync = format!(
        "C: <tag> SELECT \"Archive\"\n\
         S: * 1 EXISTS\n\
         S: * OK [UIDVALIDITY 22] UIDVALIDITY value\n\
         S: * OK [UIDNEXT 8] The next unique identifier value\n\
         S: <tag> OK [READ-WRITE] SELECT completed.\n\
         C: <tag> UID SEARCH ALL\n\
         S: * SEARCH 7\n\
         S: <tag> OK SEARCH completed.\n\
         C: <tag> UID FETCH 7 (UID FLAGS RFC822.SIZE INTERNALDATE BODY.PEEK[HEADER] BODYSTRUCTURE)\n\
         {}\n\
         S: <tag> OK FETCH completed.\n",
        header_fetch(1, 7, "\\Seen", "")
    );
    let script = old_server(&format!(
        "C: <tag> UID SEARCH DELETED\n\
         S: * SEARCH\n\
         S: <tag> OK SEARCH completed.\n\
         C: <tag> UID COPY 38 \"Archive\"\n\
         S: <tag> OK COPY completed.\n\
         C: <tag> UID STORE 38 +FLAGS.SILENT (\\Deleted)\n\
         S: <tag> OK STORE completed.\n\
         C: <tag> EXPUNGE\n\
         S: * 3 EXPUNGE\n\
         S: <tag> OK EXPUNGE completed.\n{archive_sync}"
    ));
    let replay = serve(&script);
    let mut conn = open(&replay, Provider::Other, false).await.unwrap();
    let (_dir, store) = store();
    let (id, archive) = with_message(&store, 38);
    let moved = conn.move_message(&store, id, archive, 1000).await.unwrap();
    assert!(moved.is_none());
    let m = store.lock().unwrap().message(id).unwrap().unwrap();
    assert_eq!((m.folder_id, m.uid), (archive, None));
    let undo = store.lock().unwrap().undo_entries(1001).unwrap();
    let u: crate::MoveUndo = serde_json::from_slice(&undo[0].payload).unwrap();
    assert_eq!(u.rfc_message_id.as_deref(), Some("g1@example.com"));
    assert_eq!((u.from_uid, u.to_uid, u.to_uidvalidity), (Some(38), None, None));

    let s = sync_named(&mut conn, &store, "Archive", &Policy::default()).await;
    assert_eq!(s.added, 0);
    let m = store.lock().unwrap().message(id).unwrap().unwrap();
    assert_eq!((m.folder_id, m.uid), (archive, Some(7)));
    drop(conn);
    replay.finish().unwrap();
}

#[tokio::test]
async fn without_uidplus_other_deleted_messages_are_not_expunged_with_ours() {
    let script = old_server(
        "C: <tag> UID SEARCH DELETED\n\
         S: * SEARCH 12\n\
         S: <tag> OK SEARCH completed.\n",
    );
    let replay = serve(&script);
    let mut conn = open(&replay, Provider::Other, false).await.unwrap();
    let (_dir, store) = store();
    let (id, archive) = with_message(&store, 38);
    let err = conn
        .move_message(&store, id, archive, 1000)
        .await
        .err()
        .unwrap();
    assert!(matches!(err, Error::Refused(_)), "{err:?}");
    // Nothing was copied, and the row stays where it was.
    assert_eq!(
        store.lock().unwrap().message(id).unwrap().unwrap().uid,
        Some(38)
    );
    drop(conn);
    replay.finish().unwrap();
}
