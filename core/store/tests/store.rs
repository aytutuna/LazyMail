use std::sync::Arc;

use lazymail_store::*;
use tempfile::TempDir;

fn open(dir: &TempDir) -> (Store, StoreKey, Arc<TestWrapper>) {
    let wrapper = Arc::new(TestWrapper::new());
    let key = StoreKey::generate();
    let store = Store::open(dir.path(), &key, wrapper.clone()).unwrap();
    (store, key, wrapper)
}

fn msg(folder_id: i64, subject: &str, body: &str, date: i64) -> NewMessage {
    NewMessage {
        folder_id,
        subject: subject.into(),
        from_name: "Ann".into(),
        from_addr: "ann@example.com".into(),
        to: "bob@example.com".into(),
        date,
        body_text: Some(body.into()),
        ..Default::default()
    }
}

fn q(text: &str) -> SearchQuery {
    SearchQuery {
        text: text.into(),
        limit: 50,
        ..Default::default()
    }
}

#[test]
fn reopen_keeps_data_and_wrong_key_is_refused() {
    let dir = TempDir::new().unwrap();
    let (store, key, wrapper) = open(&dir);
    assert_eq!(store.schema_version().unwrap(), 1);
    let f = store.upsert_folder("INBOX", Some("inbox")).unwrap();
    store
        .insert_message(&msg(f.id, "hello", "world", 1))
        .unwrap();
    drop(store);

    let store = Store::open(dir.path(), &key, wrapper.clone()).unwrap();
    assert_eq!(store.search(&q("world")).unwrap().len(), 1);
    drop(store);

    let err = Store::open(dir.path(), &StoreKey::generate(), wrapper)
        .err()
        .unwrap();
    assert!(matches!(err, Error::WrongKey));
}

#[test]
fn database_file_is_encrypted() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let f = store.upsert_folder("INBOX", None).unwrap();
    store
        .insert_message(&msg(f.id, "confidential-subject", "x", 1))
        .unwrap();
    drop(store);
    let raw = std::fs::read(dir.path().join("mail.db")).unwrap();
    assert!(!raw.starts_with(b"SQLite format 3"));
    assert!(!raw.windows(20).any(|w| w == b"confidential-subject"));
}

#[test]
fn newer_schema_is_refused() {
    let dir = TempDir::new().unwrap();
    let (store, key, wrapper) = open(&dir);
    drop(store);
    let conn = rusqlite::Connection::open(dir.path().join("mail.db")).unwrap();
    conn.pragma_update(None, "key", format!("x'{}'", hex(key.as_bytes())))
        .unwrap();
    conn.pragma_update(None, "user_version", 99).unwrap();
    drop(conn);
    assert!(matches!(
        Store::open(dir.path(), &key, wrapper).err().unwrap(),
        Error::TooNew(99)
    ));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn key_file_round_trip() {
    let dir = TempDir::new().unwrap();
    let w = TestWrapper::new();
    let path = dir.path().join("account.key");
    let a = load_or_create_key(&path, &w).unwrap();
    let b = load_or_create_key(&path, &w).unwrap();
    assert_eq!(a.as_bytes(), b.as_bytes());
    assert!(load_or_create_key(&path, &TestWrapper::new()).is_err());
}

#[test]
fn folder_sync_state_and_reset() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let f = store.upsert_folder("INBOX", None).unwrap();
    let again = store.upsert_folder("INBOX", Some("inbox")).unwrap();
    assert_eq!(again.id, f.id);
    assert_eq!(again.role.as_deref(), Some("inbox"));

    let state = SyncState {
        uidvalidity: Some(7),
        uidnext: Some(100),
        highestmodseq: Some(1 << 40),
        delta_link: Some("https://graph/delta?x".into()),
    };
    store.set_sync_state(f.id, &state).unwrap();
    assert_eq!(store.folder(f.id).unwrap().unwrap().sync, state);

    let mut m = msg(f.id, "a", "b", 1);
    m.uid = Some(5);
    store.insert_message(&m).unwrap();
    store.reset_folder(f.id).unwrap();
    assert_eq!(
        store.folder(f.id).unwrap().unwrap().sync,
        SyncState::default()
    );
    assert!(store.folder_uids(f.id).unwrap().is_empty());
}

#[test]
fn message_round_trip_with_ids_flags_labels() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let f = store.upsert_folder("INBOX", None).unwrap();
    let mut m = msg(f.id, "Subject", "Body text", 1000);
    m.uid = Some(42);
    m.gm_msgid = Some(1_234_567_890_123_456_789);
    m.graph_id = Some("AAMk".into());
    m.message_id = Some("<a@x>".into());
    m.flags = Flags {
        seen: true,
        flagged: true,
        ..Default::default()
    };
    m.labels = vec!["Work".into(), "Important".into()];
    m.attachments = vec![NewAttachment {
        filename: "a.pdf".into(),
        mime: "application/pdf".into(),
        size: 10,
        content_id: None,
        part: "2".into(),
    }];
    let id = store.insert_message(&m).unwrap();

    let got = store.message(id).unwrap().unwrap();
    assert_eq!(got.uid, Some(42));
    assert_eq!(got.gm_msgid, m.gm_msgid);
    assert_eq!(got.graph_id.as_deref(), Some("AAMk"));
    assert_eq!(got.flags, m.flags);
    assert_eq!(got.labels, vec!["Important", "Work"]);
    assert!(got.has_attachments);
    assert_eq!(got.attachments.len(), 1);
    assert!(!got.attachments[0].stored);
    assert_eq!(store.find_by_uid(f.id, 42).unwrap(), Some(id));
    assert_eq!(store.find_by_graph_id("AAMk").unwrap(), Some(id));

    store.set_flags(id, Flags::default()).unwrap();
    store.set_labels(id, &["Home".to_string()]).unwrap();
    let got = store.message(id).unwrap().unwrap();
    assert_eq!(got.flags, Flags::default());
    assert_eq!(got.labels, vec!["Home"]);

    // the same UID twice in a folder is refused and leaves nothing behind
    assert!(store.insert_message(&m).is_err());
    assert_eq!(store.folder_uids(f.id).unwrap().len(), 1);
}

#[test]
fn threads_follow_references_in_any_arrival_order() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let f = store.upsert_folder("INBOX", None).unwrap();
    let mk = |id: &str, reply: Option<&str>, refs: &[&str], date| {
        let mut m = msg(f.id, "t", "b", date);
        m.message_id = Some(id.into());
        m.in_reply_to = reply.map(Into::into);
        m.references = refs.iter().map(|s| s.to_string()).collect();
        m
    };
    // the reply of a reply arrives first, then an unrelated mail, then the root, then the middle
    let c = store
        .insert_message(&mk("<c>", Some("<b>"), &["<a>", "<b>"], 3))
        .unwrap();
    let z = store.insert_message(&mk("<z>", None, &[], 4)).unwrap();
    let a = store.insert_message(&mk("<a>", None, &[], 1)).unwrap();
    let b = store
        .insert_message(&mk("<b>", Some("<a>"), &["<a>"], 2))
        .unwrap();

    let t = |id| store.message(id).unwrap().unwrap().thread_id;
    assert_eq!(t(a), t(b));
    assert_eq!(t(b), t(c));
    assert_ne!(t(a), t(z));
    assert_eq!(store.thread_messages(t(a)).unwrap(), vec![a, b, c]);

    store.delete_message(z).unwrap();
    assert!(store.thread_messages(t(a)).unwrap().len() == 3);
}

#[test]
fn attachments_are_encrypted_on_disk_and_evictable() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let f = store.upsert_folder("INBOX", None).unwrap();
    let mut m = msg(f.id, "s", "b", 1);
    m.attachments = vec![NewAttachment {
        filename: "n.txt".into(),
        mime: "text/plain".into(),
        size: 20,
        part: "2".into(),
        content_id: None,
    }];
    let id = store.insert_message(&m).unwrap();
    let att = store.message(id).unwrap().unwrap().attachments[0].id;

    assert_eq!(store.attachment_data(att).unwrap(), None);
    store
        .put_attachment_data(att, b"top secret attachment")
        .unwrap();
    assert_eq!(
        store.attachment_data(att).unwrap().unwrap(),
        b"top secret attachment"
    );
    assert!(store.message(id).unwrap().unwrap().attachments[0].stored);

    let files: Vec<_> = std::fs::read_dir(dir.path().join("attachments"))
        .unwrap()
        .collect();
    assert_eq!(files.len(), 1);
    let path = files[0].as_ref().unwrap().path();
    let raw = std::fs::read(&path).unwrap();
    assert!(!raw.windows(10).any(|w| w == b"top secret"));

    // replacing leaves one file; a flipped bit is detected
    store.put_attachment_data(att, b"second").unwrap();
    assert_eq!(
        std::fs::read_dir(dir.path().join("attachments"))
            .unwrap()
            .count(),
        1
    );
    let path = std::fs::read_dir(dir.path().join("attachments"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut raw = std::fs::read(&path).unwrap();
    *raw.last_mut().unwrap() ^= 1;
    std::fs::write(&path, raw).unwrap();
    assert!(matches!(store.attachment_data(att), Err(Error::Corrupt)));
}

#[test]
fn deleting_a_message_removes_its_files() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let f = store.upsert_folder("INBOX", None).unwrap();
    let mut m = msg(f.id, "s", "b", 1);
    m.attachments = vec![NewAttachment {
        filename: "n".into(),
        mime: "x/y".into(),
        size: 1,
        part: "2".into(),
        content_id: None,
    }];
    let id = store.insert_message(&m).unwrap();
    let att = store.message(id).unwrap().unwrap().attachments[0].id;
    store.put_attachment_data(att, b"x").unwrap();
    store.delete_message(id).unwrap();
    assert_eq!(
        std::fs::read_dir(dir.path().join("attachments"))
            .unwrap()
            .count(),
        0
    );
    assert!(store.message(id).unwrap().is_none());
    assert!(store.search(&q("b")).unwrap().is_empty());
}

#[test]
fn secrets_are_wrapped_in_the_table() {
    let dir = TempDir::new().unwrap();
    let (store, key, wrapper) = open(&dir);
    store.set_secret("imap-password", b"hunter2").unwrap();
    store.set_secret("graph-refresh", b"tok").unwrap();
    assert_eq!(store.secret("imap-password").unwrap().unwrap(), b"hunter2");
    store.set_secret("imap-password", b"hunter3").unwrap();
    assert_eq!(store.secret("imap-password").unwrap().unwrap(), b"hunter3");
    assert_eq!(
        store.secret_names().unwrap(),
        vec!["graph-refresh", "imap-password"]
    );
    store.delete_secret("graph-refresh").unwrap();
    assert_eq!(store.secret("graph-refresh").unwrap(), None);
    drop(store);

    // the database key alone does not open secrets: another wrapper fails
    let store = Store::open(dir.path(), &key, Arc::new(TestWrapper::new())).unwrap();
    assert!(store.secret("imap-password").is_err());
    let store2 = Store::open(dir.path(), &key, wrapper);
    drop(store);
    assert_eq!(
        store2.unwrap().secret("imap-password").unwrap().unwrap(),
        b"hunter3"
    );
}

#[test]
fn outbox_lifecycle() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let a = store.outbox_enqueue("<m1@x>", b"raw one", 100).unwrap();
    let b = store.outbox_enqueue("<m2@x>", b"raw two", 200).unwrap();
    assert!(store.outbox_enqueue("<m1@x>", b"dup", 300).is_err());

    assert_eq!(store.outbox_due(150).unwrap().len(), 1);
    assert_eq!(store.outbox_due(250).unwrap().len(), 2);

    store.outbox_begin_send(a).unwrap();
    assert_eq!(store.outbox_due(250).unwrap().len(), 1);
    assert_eq!(store.outbox_requeue_interrupted(260).unwrap(), 1);
    assert_eq!(
        store.outbox_item(a).unwrap().unwrap().state,
        OutboxState::Queued
    );

    store.outbox_begin_send(a).unwrap();
    store.outbox_fail(a, "timeout", Some(400)).unwrap();
    let it = store.outbox_item(a).unwrap().unwrap();
    assert_eq!(
        (it.state, it.attempts, it.next_try),
        (OutboxState::Queued, 1, 400)
    );
    assert_eq!(it.message_id, "<m1@x>");
    assert_eq!(it.raw, b"raw one");
    assert_eq!(store.outbox_due(399).unwrap().len(), 1);
    assert_eq!(store.outbox_due(400).unwrap().len(), 2);

    store.outbox_fail(b, "550 rejected", None).unwrap();
    let it = store.outbox_item(b).unwrap().unwrap();
    assert_eq!(
        (it.state, it.last_error.as_deref()),
        (OutboxState::Failed, Some("550 rejected"))
    );
    assert_eq!(store.outbox_due(1000).unwrap().len(), 1);
    store.outbox_requeue(b, 500).unwrap();
    assert_eq!(store.outbox_due(1000).unwrap().len(), 2);

    store.outbox_mark_sent(a).unwrap();
    assert_eq!(
        store.outbox_item(a).unwrap().unwrap().state,
        OutboxState::Sent
    );
    store.outbox_remove(a).unwrap();
    assert_eq!(store.outbox_list().unwrap().len(), 1);
}

#[test]
fn settings_log_orders_changes() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let s1 = store
        .record_setting("theme", Some(b"dark"), 10, "pc")
        .unwrap();
    let s2 = store.record_setting("theme", None, 20, "phone").unwrap();
    assert!(s2 > s1);
    let all = store.settings_since(0).unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].value.as_deref(), Some(&b"dark"[..]));
    assert_eq!(all[1].value, None);
    assert_eq!(all[1].device, "phone");
    assert_eq!(store.settings_since(s1).unwrap().len(), 1);
}

#[test]
fn undo_entries_last_thirty_days() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let day = 86_400;
    let old = store.push_undo("move", b"{}", 0).unwrap();
    let new = store.push_undo("archive", b"{\"a\":1}", 10 * day).unwrap();

    let at = 29 * day;
    assert_eq!(store.undo_entries(at).unwrap().len(), 2);
    let at = 31 * day;
    let list = store.undo_entries(at).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, new);
    assert!(store.take_undo(old, at).unwrap().is_none());
    assert_eq!(store.purge_undo(at).unwrap(), 1);
    let e = store.take_undo(new, at).unwrap().unwrap();
    assert_eq!(e.kind, "archive");
    assert_eq!(e.expires, 40 * day);
    assert!(store.take_undo(new, at).unwrap().is_none());
}

#[test]
fn atomic_rolls_back() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let r: Result<()> = store.atomic(|s| {
        s.upsert_folder("A", None)?;
        s.atomic(|s| s.upsert_folder("B", None).map(|_| ()))?;
        Err(Error::NotFound)
    });
    assert!(r.is_err());
    assert!(store.folders().unwrap().is_empty());
}

#[test]
fn search_words_prefix_snippet_and_updates() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let f = store.upsert_folder("INBOX", None).unwrap();
    let a = store
        .insert_message(&msg(
            f.id,
            "Quarterly report",
            "The invoice for the café is attached",
            10,
        ))
        .unwrap();
    let b = store
        .insert_message(&msg(f.id, "Lunch", "Shall we meet for lunch tomorrow", 20))
        .unwrap();

    let hits = store.search(&q("invoice")).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].message_id, a);
    assert!(hits[0]
        .snippet
        .contains(&format!("{MARK_START}invoice{MARK_END}")));

    // prefix on the last word, accents folded, several words are ANDed
    assert_eq!(store.search(&q("invo")).unwrap().len(), 1);
    assert_eq!(store.search(&q("cafe")).unwrap().len(), 1);
    assert_eq!(store.search(&q("meet lunch")).unwrap()[0].message_id, b);
    assert!(store.search(&q("invoice lunch")).unwrap().is_empty());
    // quotes and operators in the text are plain words
    assert!(store.search(&q("\"invoice\" OR lunch")).unwrap().is_empty());
    // sender and subject are indexed
    assert_eq!(store.search(&q("quarterly")).unwrap().len(), 1);
    assert_eq!(store.search(&q("ann")).unwrap().len(), 2);

    store
        .set_bodies(a, Some("totally different words"), None)
        .unwrap();
    assert!(store.search(&q("invoice")).unwrap().is_empty());
    assert_eq!(store.search(&q("different")).unwrap().len(), 1);
}

#[test]
fn search_filters_and_order() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let inbox = store.upsert_folder("INBOX", None).unwrap();
    let sent = store.upsert_folder("Sent", None).unwrap();
    let mut ids = Vec::new();
    for i in 0..6 {
        let mut m = msg(
            if i % 2 == 0 { inbox.id } else { sent.id },
            &format!("topic {i}"),
            "common body",
            100 * i,
        );
        m.from_addr = if i < 3 {
            "alice@a.org".into()
        } else {
            "bob@b.org".into()
        };
        m.from_name = String::new();
        m.to = if i == 5 {
            "carol@c.org".into()
        } else {
            "me@x".into()
        };
        m.flags = Flags {
            seen: i != 1,
            flagged: i == 4,
            ..Default::default()
        };
        if i == 2 {
            m.attachments = vec![NewAttachment {
                filename: "f".into(),
                mime: "a/b".into(),
                size: 1,
                part: "2".into(),
                content_id: None,
            }];
        }
        ids.push(store.insert_message(&m).unwrap());
    }
    let ids_of = |query: SearchQuery| -> Vec<i64> {
        store
            .search(&query)
            .unwrap()
            .iter()
            .map(|h| h.message_id)
            .collect()
    };

    let newest_first: Vec<i64> = ids.iter().rev().copied().collect();
    assert_eq!(ids_of(q("common")), newest_first);
    assert_eq!(ids_of(SearchQuery::default()), newest_first);
    assert_eq!(
        ids_of(SearchQuery {
            from: Some("alice".into()),
            ..Default::default()
        }),
        vec![ids[2], ids[1], ids[0]]
    );
    assert_eq!(
        ids_of(SearchQuery {
            to: Some("carol".into()),
            ..Default::default()
        }),
        vec![ids[5]]
    );
    assert_eq!(
        ids_of(SearchQuery {
            subject: Some("topic 3".into()),
            ..Default::default()
        }),
        vec![ids[3]]
    );
    assert_eq!(
        ids_of(SearchQuery {
            folder_id: Some(sent.id),
            ..q("common")
        }),
        vec![ids[5], ids[3], ids[1]]
    );
    assert_eq!(
        ids_of(SearchQuery {
            after: Some(100),
            before: Some(400),
            ..q("common")
        }),
        vec![ids[3], ids[2], ids[1]]
    );
    assert_eq!(
        ids_of(SearchQuery {
            has_attachment: true,
            ..q("common")
        }),
        vec![ids[2]]
    );
    assert_eq!(
        ids_of(SearchQuery {
            unread: true,
            ..q("common")
        }),
        vec![ids[1]]
    );
    assert_eq!(
        ids_of(SearchQuery {
            flagged: true,
            ..q("common")
        }),
        vec![ids[4]]
    );
    assert_eq!(
        ids_of(SearchQuery {
            limit: 2,
            offset: 1,
            ..q("common")
        }),
        vec![ids[4], ids[3]]
    );
    // a literal percent sign is not a wildcard
    assert!(ids_of(SearchQuery {
        from: Some("%".into()),
        ..Default::default()
    })
    .is_empty());
}

#[test]
fn search_chinese_japanese_korean_thai() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let f = store.upsert_folder("INBOX", None).unwrap();
    let zh = store
        .insert_message(&msg(
            f.id,
            "会议",
            "明天下午三点在北京办公室开会讨论预算",
            1,
        ))
        .unwrap();
    let ja = store
        .insert_message(&msg(
            f.id,
            "お知らせ",
            "来週の打ち合わせは東京本社で行います",
            2,
        ))
        .unwrap();
    let ko = store
        .insert_message(&msg(f.id, "안내", "내일 오후 회의실에서 만나요", 3))
        .unwrap();
    let th = store
        .insert_message(&msg(f.id, "ประชุม", "พรุ่งนี้เจอกันที่สำนักงานกรุงเทพ", 4))
        .unwrap();
    let en = store
        .insert_message(&msg(f.id, "plain", "just english here", 5))
        .unwrap();

    let one = |text: &str| -> Vec<i64> {
        store
            .search(&q(text))
            .unwrap()
            .iter()
            .map(|h| h.message_id)
            .collect()
    };
    // three characters or more go through the trigram index
    assert_eq!(one("办公室"), vec![zh]);
    assert_eq!(one("北京办公"), vec![zh]);
    assert_eq!(one("東京本社"), vec![ja]);
    assert_eq!(one("회의실"), vec![ko]);
    assert_eq!(one("สำนักงาน"), vec![th]);
    let hit = &store.search(&q("办公室")).unwrap()[0];
    assert!(hit.snippet.contains(MARK_START));
    // two characters are too short for trigrams and fall back to a scan
    assert_eq!(one("预算"), vec![zh]);
    assert_eq!(one("会议"), vec![zh]);
    assert_eq!(one("東京"), vec![ja]);
    // latin text still works next to them
    assert_eq!(one("english"), vec![en]);
}

#[test]
fn prune_bodies_keeps_headers_and_subject_search() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let f = store.upsert_folder("INBOX", None).unwrap();
    let mut old = msg(f.id, "old subject", "old secretword body", 100);
    old.body_html = Some("<p>old</p>".into());
    old.attachments = vec![NewAttachment {
        filename: "n".into(),
        mime: "x/y".into(),
        size: 1,
        part: "2".into(),
        content_id: None,
    }];
    let old = store.insert_message(&old).unwrap();
    let new = store
        .insert_message(&msg(f.id, "new subject", "new secretword body", 1000))
        .unwrap();
    let att = store.message(old).unwrap().unwrap().attachments[0].id;
    store.put_attachment_data(att, b"bytes").unwrap();

    assert_eq!(store.prune_bodies(500).unwrap(), 1);
    assert_eq!(store.prune_bodies(500).unwrap(), 0);

    let o = store.message(old).unwrap().unwrap();
    assert_eq!((o.body_text, o.body_html), (None, None));
    assert_eq!(o.subject, "old subject");
    assert_eq!(o.preview, "old secretword body");
    assert!(!o.attachments[0].stored);
    assert_eq!(
        std::fs::read_dir(dir.path().join("attachments"))
            .unwrap()
            .count(),
        0
    );
    assert!(store.message(new).unwrap().unwrap().body_text.is_some());

    let hits: Vec<i64> = store
        .search(&q("secretword"))
        .unwrap()
        .iter()
        .map(|h| h.message_id)
        .collect();
    assert_eq!(hits, vec![new]);
    assert_eq!(store.search(&q("old subject")).unwrap().len(), 1);
}

/// Desktop budget. The plan allows 300 ms on phones, which are several times slower, so run
/// this test on a device before trusting that number.
/// cargo test --release -p lazymail-store -- --ignored --nocapture
#[test]
#[ignore]
fn search_100k_under_200_ms() {
    use std::time::Instant;

    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let inbox = store.upsert_folder("INBOX", None).unwrap();
    let archive = store.upsert_folder("Archive", None).unwrap();

    let mut seed = 0x2545F4914F6CDD1Du64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let vocab: Vec<String> = (0..20_000)
        .map(|i| format!("w{:x}{}", i * 2654435761u64 % 99991, i))
        .collect();
    // words are drawn with a skew so a few are very common, as in real mail
    let word = |n: &mut dyn FnMut() -> u64| {
        let r = (n() % 1000) as usize;
        let idx = if r < 600 {
            r % 50
        } else {
            (n() as usize) % vocab.len()
        };
        vocab[idx].clone()
    };

    let han: Vec<char> = (0x4E00u32..0x4E00 + 60)
        .map(|c| char::from_u32(c).unwrap())
        .collect();
    let thai: Vec<char> = (0x0E01u32..0x0E01 + 40)
        .map(|c| char::from_u32(c).unwrap())
        .collect();

    let start = Instant::now();
    store
        .atomic(|s| {
            for i in 0..100_000i64 {
                let mut body: Vec<String> = (0..60).map(|_| word(&mut next)).collect();
                if i % 10 == 0 {
                    let pool = if i % 20 == 0 { &han } else { &thai };
                    body.push(
                        (0..80)
                            .map(|_| pool[(next() as usize) % pool.len()])
                            .collect(),
                    );
                }
                let m = NewMessage {
                    folder_id: if i % 5 == 0 { archive.id } else { inbox.id },
                    uid: Some(i as u32 + 1),
                    message_id: Some(format!("<{i}@perf>")),
                    subject: format!(
                        "{} {} {}",
                        word(&mut next),
                        word(&mut next),
                        word(&mut next)
                    ),
                    from_name: format!("Sender {}", i % 500),
                    from_addr: format!("user{}@example.com", i % 500),
                    to: "me@example.com".into(),
                    date: 1_700_000_000 + i * 60,
                    flags: Flags {
                        seen: i % 3 != 0,
                        flagged: i % 50 == 0,
                        ..Default::default()
                    },
                    body_text: Some(body.join(" ")),
                    ..Default::default()
                };
                s.insert_message(&m)?;
            }
            Ok(())
        })
        .unwrap();
    println!("filled 100000 emails in {:?}", start.elapsed());

    let common = vocab[3].clone();
    let rare = vocab[19_999].clone();
    let cases: Vec<(&str, SearchQuery)> = vec![
        (
            "common word",
            SearchQuery {
                limit: 50,
                ..q(&common)
            },
        ),
        (
            "two common words",
            SearchQuery {
                limit: 50,
                ..q(&format!("{} {}", vocab[1], vocab[2]))
            },
        ),
        (
            "rare word",
            SearchQuery {
                limit: 50,
                ..q(&rare)
            },
        ),
        (
            "prefix",
            SearchQuery {
                limit: 50,
                ..q(&common[..3])
            },
        ),
        (
            "common + folder + unread",
            SearchQuery {
                folder_id: Some(inbox.id),
                unread: true,
                limit: 50,
                ..q(&common)
            },
        ),
        (
            "common + date range",
            SearchQuery {
                after: Some(1_700_000_000 + 40_000 * 60),
                before: Some(1_700_000_000 + 60_000 * 60),
                limit: 50,
                ..q(&common)
            },
        ),
        (
            "sender filter only",
            SearchQuery {
                from: Some("user42@".into()),
                limit: 50,
                ..Default::default()
            },
        ),
        (
            "flagged only",
            SearchQuery {
                flagged: true,
                limit: 50,
                ..Default::default()
            },
        ),
        (
            "two-character CJK",
            SearchQuery {
                limit: 50,
                ..q(&han[3..5].iter().collect::<String>())
            },
        ),
        (
            "three-character CJK",
            SearchQuery {
                limit: 50,
                ..q(&han[3..6].iter().collect::<String>())
            },
        ),
        (
            "two-character Thai",
            SearchQuery {
                limit: 50,
                ..q(&thai[3..5].iter().collect::<String>())
            },
        ),
        (
            "three-character Thai",
            SearchQuery {
                limit: 50,
                ..q(&thai[3..6].iter().collect::<String>())
            },
        ),
        (
            "one-character CJK",
            SearchQuery {
                limit: 50,
                ..q(&han[3..4].iter().collect::<String>())
            },
        ),
        (
            "word + from",
            SearchQuery {
                from: Some("user42@".into()),
                limit: 50,
                ..q(&common)
            },
        ),
    ];
    let mut worst = std::time::Duration::ZERO;
    for (name, query) in cases {
        let mut runs: Vec<_> = (0..3)
            .map(|_| {
                let t = Instant::now();
                let hits = store.search(&query).unwrap();
                (t.elapsed(), hits.len())
            })
            .collect();
        runs.sort();
        let (d, hits) = (runs[1].0, runs[1].1);
        println!("{name}: {hits} hits in {d:?} (median of 3)");
        worst = worst.max(d);
    }
    println!("worst {worst:?}");
    assert!(worst.as_millis() < 200, "slowest search took {worst:?}");
}

fn attachment_msg(folder: i64, subject: &str, uid: u32) -> NewMessage {
    let mut m = msg(folder, subject, "b", 1);
    m.uid = Some(uid);
    m.attachments = vec![NewAttachment {
        filename: "a.bin".into(),
        mime: "application/octet-stream".into(),
        size: 3,
        part: "2".into(),
        content_id: None,
    }];
    m
}

fn blob_count(dir: &TempDir) -> usize {
    std::fs::read_dir(dir.path().join("attachments"))
        .unwrap()
        .count()
}

#[test]
fn files_survive_a_rolled_back_delete() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let f = store.upsert_folder("INBOX", None).unwrap();
    let id = store.insert_message(&attachment_msg(f.id, "s", 1)).unwrap();
    let att = store.message(id).unwrap().unwrap().attachments[0].id;
    store.put_attachment_data(att, b"abc").unwrap();

    let r: Result<()> = store.atomic(|s| {
        s.delete_message(id)?;
        s.insert_message(&attachment_msg(f.id, "moved", 1))?;
        s.insert_message(&attachment_msg(f.id, "dup", 1))?;
        Ok(())
    });
    assert!(r.is_err());
    assert_eq!(store.attachment_data(att).unwrap().unwrap(), b"abc");
    assert_eq!(blob_count(&dir), 1);

    store.atomic(|s| s.delete_message(id)).unwrap();
    assert_eq!(blob_count(&dir), 0);
}

#[test]
fn a_missing_attachment_file_reads_as_not_downloaded() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let f = store.upsert_folder("INBOX", None).unwrap();
    let id = store.insert_message(&attachment_msg(f.id, "s", 1)).unwrap();
    let att = store.message(id).unwrap().unwrap().attachments[0].id;
    store.put_attachment_data(att, b"abc").unwrap();
    for e in std::fs::read_dir(dir.path().join("attachments")).unwrap() {
        std::fs::remove_file(e.unwrap().path()).unwrap();
    }
    assert_eq!(store.attachment_data(att).unwrap(), None);
    assert!(!store.message(id).unwrap().unwrap().attachments[0].stored);
}

#[test]
fn stray_attachment_files_are_swept_on_open() {
    let dir = TempDir::new().unwrap();
    let (store, key, wrapper) = open(&dir);
    assert!(store.put_attachment_data(99, b"x").is_err());
    assert_eq!(blob_count(&dir), 0);
    drop(store);
    std::fs::write(dir.path().join("attachments").join("leftover"), b"x").unwrap();
    Store::open(dir.path(), &key, wrapper).unwrap();
    assert_eq!(blob_count(&dir), 0);
}

#[test]
fn moving_keeps_the_row_attachments_and_thread() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let inbox = store.upsert_folder("INBOX", None).unwrap();
    let trash = store.upsert_folder("Trash", None).unwrap();
    let id = store
        .insert_message(&attachment_msg(inbox.id, "s", 7))
        .unwrap();
    let att = store.message(id).unwrap().unwrap().attachments[0].id;
    store.put_attachment_data(att, b"abc").unwrap();
    let thread = store.message(id).unwrap().unwrap().thread_id;

    store.move_message(id, trash.id, Some(3)).unwrap();
    let m = store.message(id).unwrap().unwrap();
    assert_eq!(
        (m.folder_id, m.uid, m.thread_id),
        (trash.id, Some(3), thread)
    );
    assert_eq!(store.find_by_uid(inbox.id, 7).unwrap(), None);
    assert_eq!(store.find_by_uid(trash.id, 3).unwrap(), Some(id));
    assert_eq!(store.attachment_data(att).unwrap().unwrap(), b"abc");

    store.set_ids(id, Some(9), Some("AAMk")).unwrap();
    assert_eq!(store.find_by_graph_id("AAMk").unwrap(), Some(id));
    assert!(store.move_message(999, trash.id, None).is_err());
}

#[test]
fn a_gmail_message_with_two_labels_is_found_once_per_label() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let all = store.upsert_folder("[Gmail]/All Mail", None).unwrap();
    let mut m = msg(all.id, "Quarterly plan", "numbers", 5);
    m.gm_msgid = Some(1111);
    m.labels = vec!["\\Inbox".into(), "Work".into()];
    let id = store.insert_message(&m).unwrap();
    let mut other = msg(all.id, "Quarterly lunch", "food", 6);
    other.gm_msgid = Some(2222);
    other.labels = vec!["Home".into()];
    store.insert_message(&other).unwrap();
    assert!(store.insert_message(&m).is_err());
    assert_eq!(store.find_by_gm_msgid(1111).unwrap(), Some(id));

    let ids = |label: Option<&str>| -> Vec<i64> {
        store
            .search(&SearchQuery {
                label: label.map(str::to_string),
                ..q("quarterly")
            })
            .unwrap()
            .iter()
            .map(|h| h.message_id)
            .collect()
    };
    assert_eq!(ids(Some("Work")), vec![id]);
    assert_eq!(ids(Some("\\Inbox")), vec![id]);
    assert_eq!(ids(Some("Home")).len(), 1);
    assert_eq!(ids(None).len(), 2);
}

#[test]
fn replies_to_a_missing_root_share_a_thread() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let f = store.upsert_folder("INBOX", None).unwrap();
    let reply = |mid: &str, date: i64| {
        let mut m = msg(f.id, "Re: plan", "b", date);
        m.message_id = Some(mid.into());
        m.references = vec!["<root@x>".into()];
        m
    };
    let a = store.insert_message(&reply("<a@x>", 1)).unwrap();
    let b = store.insert_message(&reply("<b@x>", 2)).unwrap();
    let unrelated = store.insert_message(&msg(f.id, "other", "b", 3)).unwrap();
    let t = |id| store.message(id).unwrap().unwrap().thread_id;
    assert_eq!(t(a), t(b));
    assert_ne!(t(a), t(unrelated));
    let m = store.message(a).unwrap().unwrap();
    assert_eq!(m.references, vec!["<root@x>".to_string()]);
}

#[test]
fn html_only_mail_is_searchable_and_previewed() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let f = store.upsert_folder("INBOX", None).unwrap();
    let mut m = msg(f.id, "News", "", 1);
    m.body_text = None;
    m.body_html =
        Some("<style>p{color:red}</style><p>Fresh &amp; <b>zebrafish</b> arrivals</p>".into());
    let a = store.insert_message(&m).unwrap();
    let hits = store.search(&q("zebrafish")).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].message_id, a);
    assert!(!hits[0].snippet.contains("color"));
    assert!(store.search(&q("color")).unwrap().is_empty());

    let b = store.insert_message(&msg(f.id, "Later", "x", 2)).unwrap();
    store
        .set_bodies(b, None, Some("<div>quokka pastures</div>"))
        .unwrap();
    assert_eq!(store.search(&q("quokka")).unwrap().len(), 1);
    assert_eq!(
        store.message(b).unwrap().unwrap().preview,
        "quokka pastures"
    );
}

#[test]
fn control_characters_in_a_query_are_ignored() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let f = store.upsert_folder("INBOX", None).unwrap();
    store
        .insert_message(&msg(f.id, "hello", "world", 1))
        .unwrap();
    assert_eq!(store.search(&q("hel\0lo")).unwrap().len(), 1);
    assert_eq!(store.search(&q("hello\0")).unwrap().len(), 1);
    assert_eq!(store.search(&q("\0")).unwrap().len(), 1);
}

#[test]
fn inline_images_do_not_count_as_attachments() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let f = store.upsert_folder("INBOX", None).unwrap();
    let mut m = msg(f.id, "s", "b", 1);
    m.attachments = vec![NewAttachment {
        filename: "logo.png".into(),
        mime: "image/png".into(),
        size: 1,
        part: "2".into(),
        content_id: Some("<logo@x>".into()),
    }];
    let id = store.insert_message(&m).unwrap();
    assert!(!store.message(id).unwrap().unwrap().has_attachments);
}

#[test]
fn wrapped_data_is_bound_to_its_name() {
    let w = TestWrapper::new();
    let blob = w.wrap(b"a", b"one").unwrap();
    assert_eq!(w.unwrap(b"a", &blob).unwrap(), b"one");
    assert!(w.unwrap(b"b", &blob).is_err());
}

#[test]
fn only_a_queued_item_starts_sending() {
    let dir = TempDir::new().unwrap();
    let (store, _, _) = open(&dir);
    let a = store.outbox_enqueue("<m@x>", b"raw", 1).unwrap();
    store.outbox_begin_send(a).unwrap();
    assert!(store.outbox_begin_send(a).is_err());
    store.outbox_mark_sent(a).unwrap();
    assert!(store.outbox_begin_send(a).is_err());
}
