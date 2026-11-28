use std::fs;
use std::sync::Arc;
use std::time::Duration;

use lazymail_accounts::{Resource, StaticTokens, TokenError};
use lazymail_graph::{Error, Graph, Summary};
use lazymail_store::{Flags, Store, StoreKey, SyncState, TestWrapper};
use tempfile::TempDir;
use wiremock::matchers::{body_json, body_string, header, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SELECT: &str =
    "internetMessageId,subject,from,toRecipients,ccRecipients,receivedDateTime,isRead,isDraft,flag";
const M1: &str = "AAMkAGI2TGuLAAA=";
const M2: &str = "AAMkAGI2TGuMAAA=";
const M3: &str = "AAMkAGI2TGuNAAA=";

struct Env {
    server: MockServer,
    store: Store,
    graph: Graph<StaticTokens>,
    _dir: TempDir,
}

async fn env() -> Env {
    let server = MockServer::start().await;
    let tokens = StaticTokens::default();
    tokens.set("acct", Resource::Graph, Ok("tok".into()));
    let dir = TempDir::new().unwrap();
    let store = Store::open(
        dir.path(),
        &StoreKey::generate(),
        Arc::new(TestWrapper::new()),
    )
    .unwrap();
    let graph = Graph::with_base_url("acct", tokens, &server.uri());
    Env {
        server,
        store,
        graph,
        _dir: dir,
    }
}

fn fixture(env: &Env, name: &str) -> String {
    let file = format!("{}/tests/fixtures/{name}", env.manifest());
    fs::read_to_string(file)
        .unwrap()
        .replace("{{base}}", &env.server.uri())
}

impl Env {
    fn manifest(&self) -> &'static str {
        env!("CARGO_MANIFEST_DIR")
    }

    async fn json(&self, p: &str, query: &[(&str, &str)], body: String) {
        let mut m = Mock::given(method("GET")).and(path(p));
        for (k, v) in query {
            m = m.and(query_param(*k, *v));
        }
        m.respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .mount(&self.server)
            .await;
    }

    async fn mime(&self, graph_id: &str, file: &str) {
        let raw = fs::read(format!("{}/tests/fixtures/{file}", self.manifest())).unwrap();
        Mock::given(method("GET"))
            .and(path(format!("/me/messages/{graph_id}/$value")))
            .respond_with(ResponseTemplate::new(200).set_body_raw(raw, "message/rfc822"))
            .mount(&self.server)
            .await;
    }

    /// Folders and role lookups for the folder fixtures, and empty deltas for every folder but
    /// the inbox.
    async fn mailbox(&self) {
        self.json(
            "/me/mailFolders/delta",
            &[("$select", "displayName,parentFolderId")],
            fixture(self, "folders_delta_1.json"),
        )
        .await;
        self.json(
            "/me/mailFolders/delta",
            &[("$skiptoken", "folders-p2")],
            fixture(self, "folders_delta_2.json"),
        )
        .await;
        for (name, id) in [
            ("inbox", "inbox-id"),
            ("sentitems", "sent-id"),
            ("drafts", "drafts-id"),
            ("deleteditems", "deleted-id"),
            ("junkemail", "junk-id"),
        ] {
            self.json(
                &format!("/me/mailFolders/{name}"),
                &[("$select", "id")],
                format!(r#"{{"id":"{id}"}}"#),
            )
            .await;
        }
        Mock::given(method("GET"))
            .and(path("/me/mailFolders/archive"))
            .respond_with(ResponseTemplate::new(404).set_body_raw(
                r#"{"error":{"code":"ErrorFolderNotFound","message":"missing"}}"#,
                "application/json",
            ))
            .mount(&self.server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/me/mailFolders/[^/]+/messages/delta$"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                format!(
                    r#"{{"value":[],"@odata.deltaLink":"{}/me/mailFolders/x/messages/delta?$deltatoken=e"}}"#,
                    self.server.uri()
                ),
                "application/json",
            ))
            .with_priority(10)
            .mount(&self.server)
            .await;
    }

    async fn inbox(&self) {
        let p = "/me/mailFolders/inbox-id/messages/delta";
        self.json(
            p,
            &[("$select", SELECT)],
            fixture(self, "messages_delta_inbox_1.json"),
        )
        .await;
        self.json(
            p,
            &[("$skiptoken", "inbox-p2")],
            fixture(self, "messages_delta_inbox_2.json"),
        )
        .await;
        self.mime(M1, "message_1.eml").await;
        self.mime(M2, "message_2.eml").await;
        self.mime(M3, "message_3.eml").await;
    }

    fn folder(&self, role: &str) -> lazymail_store::Folder {
        self.store
            .folders()
            .unwrap()
            .into_iter()
            .find(|f| f.role.as_deref() == Some(role))
            .unwrap()
    }

    fn message(&self, graph_id: &str) -> lazymail_store::Message {
        let id = self.store.find_by_graph_id(graph_id).unwrap().unwrap();
        self.store.message(id).unwrap().unwrap()
    }
}

#[tokio::test]
async fn first_sync_downloads_folders_and_mail() {
    let e = env().await;
    e.mailbox().await;
    e.inbox().await;

    let sum = e.graph.sync(&e.store).await.unwrap().summary;
    assert_eq!(
        sum,
        Summary {
            added: 3,
            updated: 0,
            removed: 0
        }
    );

    let mut names: Vec<_> = e
        .store
        .folders()
        .unwrap()
        .into_iter()
        .map(|f| (f.name, f.role))
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            ("Deleted Items".into(), Some("trash".into())),
            ("Drafts".into(), Some("drafts".into())),
            ("Inbox".into(), Some("inbox".into())),
            ("Junk Email".into(), Some("junk".into())),
            ("Projects".into(), None),
            ("Sent Items".into(), Some("sent".into())),
        ]
    );

    let m1 = e.message(M1);
    assert_eq!(m1.subject, "Meeting notes");
    assert_eq!(m1.from_name, "Adele Vance");
    assert_eq!(m1.from_addr, "adelev@contoso.example");
    assert_eq!(m1.to, "Alex Wilber <alexw@contoso.example>");
    assert_eq!(m1.message_id.as_deref(), Some("4f8e2a@contoso.example"));
    assert_eq!(m1.date, 1772359200);
    assert_eq!(m1.flags, Flags::default());
    assert_eq!(
        m1.body_text.as_deref().map(str::trim),
        Some("Notes from today's meeting are below.")
    );
    assert!(m1.body_html.unwrap().contains("<p>Notes"));
    assert!(m1.headers.unwrap().starts_with("Received: from mail"));
    assert!(!m1.has_attachments);

    let m2 = e.message(M2);
    assert!(m2.flags.seen && m2.flags.flagged);
    assert_eq!(
        m2.to,
        "Adele Vance <adelev@contoso.example>, lynne@contoso.example"
    );
    assert_eq!(m2.cc, "diego@contoso.example");
    assert_eq!(m2.in_reply_to.as_deref(), Some("4f8e2a@contoso.example"));
    assert_eq!(m2.thread_id, m1.thread_id);
    assert!(m2.has_attachments);
    assert_eq!(m2.attachments.len(), 1);
    assert_eq!(m2.attachments[0].filename, "agenda.pdf");
    assert_eq!(m2.attachments[0].mime, "application/pdf");
    // The bytes came with the message and are kept, so opening it needs no second download.
    assert_eq!(
        e.store
            .attachment_data(m2.attachments[0].id)
            .unwrap()
            .unwrap(),
        b"%PDF-1.4
%%EOF
"
    );

    let m3 = e.message(M3);
    assert!(m3.body_html.unwrap().contains("Three things"));
    assert!(m3.body_text.unwrap().contains("Three things"));
    assert_ne!(m3.thread_id, m1.thread_id);
}

#[tokio::test]
async fn every_request_carries_the_token_and_asks_for_immutable_ids() {
    let e = env().await;
    e.mailbox().await;
    e.inbox().await;
    e.graph.sync(&e.store).await.unwrap();
    let requests = e.server.received_requests().await.unwrap();
    assert!(requests.len() > 10);
    for r in requests {
        assert_eq!(r.headers["authorization"], "Bearer tok");
        assert!(r.headers["prefer"]
            .to_str()
            .unwrap()
            .contains("IdType=\"ImmutableId\""));
    }
}

#[tokio::test]
async fn a_second_sync_applies_only_the_delta() {
    let e = env().await;
    e.mailbox().await;
    e.inbox().await;
    e.graph.sync(&e.store).await.unwrap();

    e.json(
        "/me/mailFolders/delta",
        &[("$deltatoken", "folders-1")],
        fixture(&e, "folders_delta_changes.json"),
    )
    .await;
    e.json(
        "/me/mailFolders/inbox-id/messages/delta",
        &[("$deltatoken", "inbox-1")],
        fixture(&e, "messages_delta_inbox_changes.json"),
    )
    .await;
    let before = e.server.received_requests().await.unwrap().len();

    let sum = e.graph.sync(&e.store).await.unwrap().summary;
    assert_eq!(
        sum,
        Summary {
            added: 0,
            updated: 1,
            removed: 1
        }
    );
    let names: Vec<_> = e
        .store
        .folders()
        .unwrap()
        .into_iter()
        .map(|f| f.name)
        .collect();
    assert!(names.contains(&"Projects 2026".to_string()));
    assert!(!names.contains(&"Junk Email".to_string()));

    let m1 = e.message(M1);
    assert!(m1.flags.seen && m1.flags.flagged);
    assert_eq!(e.store.find_by_graph_id(M2).unwrap(), None);
    // The changed rows were updated in place; no message body was fetched again.
    let requests = e.server.received_requests().await.unwrap();
    assert!(requests[before..]
        .iter()
        .all(|r| !r.url.path().ends_with("$value")));
}

#[tokio::test]
async fn a_dropped_delta_link_lists_the_folder_again_without_losing_rows() {
    let e = env().await;
    e.mailbox().await;
    e.inbox().await;
    e.graph.sync(&e.store).await.unwrap();
    let inbox = e.folder("inbox");
    assert!(inbox.sync.delta_link.is_some());
    let ids: Vec<_> = [M1, M2, M3]
        .iter()
        .map(|m| e.store.find_by_graph_id(m).unwrap().unwrap())
        .collect();

    Mock::given(method("GET"))
        .and(path("/me/mailFolders/inbox-id/messages/delta"))
        .and(query_param("$deltatoken", "inbox-1"))
        .respond_with(ResponseTemplate::new(410).set_body_raw(
            fixture(&e, "error_sync_state_not_found.json"),
            "application/json",
        ))
        .mount(&e.server)
        .await;
    let before = e.server.received_requests().await.unwrap().len();
    let sum = e.graph.sync_folder(&e.store, inbox.id).await.unwrap();
    assert_eq!(sum, Summary::default());
    for (m, id) in [M1, M2, M3].iter().zip(ids) {
        assert_eq!(e.store.find_by_graph_id(m).unwrap(), Some(id));
    }
    let requests = e.server.received_requests().await.unwrap();
    assert!(requests[before..]
        .iter()
        .all(|r| !r.url.path().ends_with("$value")));
}

#[tokio::test]
async fn a_full_listing_drops_rows_the_server_no_longer_has() {
    let e = env().await;
    e.mailbox().await;
    e.inbox().await;
    e.graph.sync(&e.store).await.unwrap();
    let inbox = e.folder("inbox");

    // The expired link is answered with a listing that lacks M2 and has a new message.
    Mock::given(method("GET"))
        .and(path("/me/mailFolders/inbox-id/messages/delta"))
        .and(query_param("$deltatoken", "inbox-1"))
        .respond_with(ResponseTemplate::new(410).set_body_raw(
            fixture(&e, "error_sync_state_not_found.json"),
            "application/json",
        ))
        .mount(&e.server)
        .await;
    let base = e.server.uri();
    Mock::given(method("GET"))
        .and(path("/me/mailFolders/inbox-id/messages/delta"))
        .and(query_param("$select", SELECT))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            format!(
                r#"{{"value":[{{"id":"{M1}","isRead":true,"isDraft":false}},{{"id":"{M3}","isRead":false,"isDraft":false}}],"@odata.deltaLink":"{base}/me/mailFolders/inbox-id/messages/delta?$deltatoken=inbox-9"}}"#
            ),
            "application/json",
        ))
        .with_priority(1)
        .mount(&e.server)
        .await;
    let sum = e.graph.sync_folder(&e.store, inbox.id).await.unwrap();
    assert_eq!(
        sum,
        Summary {
            added: 0,
            updated: 1,
            removed: 1
        }
    );
    assert!(e.message(M1).flags.seen);
    assert!(e.store.find_by_graph_id(M2).unwrap().is_none());
    assert!(e.store.find_by_graph_id(M3).unwrap().is_some());
    assert!(e
        .folder("inbox")
        .sync
        .delta_link
        .unwrap()
        .contains("inbox-9"));
}

#[tokio::test]
async fn a_moved_message_keeps_its_row() {
    let e = env().await;
    e.mailbox().await;
    e.inbox().await;
    e.graph.sync(&e.store).await.unwrap();
    let id = e.store.find_by_graph_id(M1).unwrap().unwrap();

    // The destination folder's delta is read before the inbox reports the removal.
    e.json(
        "/me/mailFolders/drafts-id/messages/delta",
        &[("$select", SELECT)],
        format!(
            r#"{{"value":[{{"id":"{M1}","isRead":false,"isDraft":false}}],"@odata.deltaLink":"{}/me/mailFolders/drafts-id/messages/delta?$deltatoken=d2"}}"#,
            e.server.uri()
        ),
    )
    .await;
    e.json(
        "/me/mailFolders/inbox-id/messages/delta",
        &[("$deltatoken", "inbox-1")],
        format!(
            r#"{{"value":[{{"id":"{M1}","@removed":{{"reason":"changed"}}}}],"@odata.deltaLink":"{}/me/mailFolders/inbox-id/messages/delta?$deltatoken=inbox-2"}}"#,
            e.server.uri()
        ),
    )
    .await;
    let drafts = e.folder("drafts");
    e.store
        .set_sync_state(drafts.id, &SyncState::default())
        .unwrap();
    e.graph.sync_folder(&e.store, drafts.id).await.unwrap();
    let inbox = e.folder("inbox");
    let sum = e.graph.sync_folder(&e.store, inbox.id).await.unwrap();

    assert_eq!(sum.removed, 0);
    assert_eq!(e.store.find_by_graph_id(M1).unwrap(), Some(id));
    assert_eq!(e.store.message(id).unwrap().unwrap().folder_id, drafts.id);
}

#[tokio::test]
async fn a_401_needs_sign_in() {
    let e = env().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401).set_body_raw(
            r#"{"error":{"code":"InvalidAuthenticationToken","message":"expired"}}"#,
            "application/json",
        ))
        .mount(&e.server)
        .await;
    assert!(matches!(
        e.graph.sync_folders(&e.store).await,
        Err(Error::NeedsSignIn)
    ));
}

#[tokio::test]
async fn a_missing_refresh_token_needs_sign_in() {
    let e = env().await;
    let tokens = StaticTokens::default();
    tokens.set(
        "acct",
        Resource::Graph,
        Err(TokenError::InteractionRequired),
    );
    let graph = Graph::with_base_url("acct", tokens, &e.server.uri());
    assert!(matches!(
        graph.sync_folders(&e.store).await,
        Err(Error::NeedsSignIn)
    ));
    assert!(e.server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn throttling_waits_for_retry_after_and_tries_again() {
    let e = env().await;
    for status in [429, 503] {
        Mock::given(method("GET"))
            .and(path("/me/mailFolders/delta"))
            .respond_with(ResponseTemplate::new(status).insert_header("Retry-After", "0"))
            .up_to_n_times(1)
            .mount(&e.server)
            .await;
    }
    e.mailbox().await;
    e.graph.sync_folders(&e.store).await.unwrap();
    assert_eq!(e.store.folders().unwrap().len(), 6);
    let tries = e
        .server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == "/me/mailFolders/delta")
        .count();
    // Two throttled answers, then the two pages.
    assert_eq!(tries, 4);
}

#[tokio::test]
async fn retry_after_is_waited_out() {
    let e = env().await;
    Mock::given(method("GET"))
        .and(path("/me/mailFolders/delta"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "1"))
        .up_to_n_times(1)
        .mount(&e.server)
        .await;
    e.mailbox().await;
    let start = std::time::Instant::now();
    e.graph.sync_folders(&e.store).await.unwrap();
    assert!(start.elapsed() >= Duration::from_secs(1));
}

#[tokio::test]
async fn a_long_retry_after_goes_back_to_the_caller() {
    let e = env().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "3600"))
        .mount(&e.server)
        .await;
    match e.graph.sync_folders(&e.store).await {
        Err(Error::Throttled(d)) => assert_eq!(d, Duration::from_secs(3600)),
        other => panic!("{other:?}"),
    }
    assert_eq!(e.server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn throttling_that_does_not_end_gives_up() {
    let e = env().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503).insert_header("Retry-After", "0"))
        .mount(&e.server)
        .await;
    assert!(matches!(
        e.graph.sync_folders(&e.store).await,
        Err(Error::Throttled(_))
    ));
    assert_eq!(e.server.received_requests().await.unwrap().len(), 4);
}

#[tokio::test]
async fn a_link_to_another_host_is_not_followed() {
    let e = env().await;
    e.json(
        "/me/mailFolders/delta",
        &[],
        r#"{"value":[],"@odata.nextLink":"https://elsewhere.example/me/mailFolders/delta?$skiptoken=x"}"#.into(),
    )
    .await;
    assert!(matches!(
        e.graph.sync_folders(&e.store).await,
        Err(Error::BadResponse(_))
    ));
}

#[tokio::test]
async fn flags_are_sent_then_stored() {
    let e = env().await;
    e.mailbox().await;
    e.inbox().await;
    e.graph.sync(&e.store).await.unwrap();
    let id = e.store.find_by_graph_id(M1).unwrap().unwrap();

    Mock::given(method("PATCH"))
        .and(path(format!("/me/messages/{M1}")))
        .and(body_json(serde_json::json!({
            "isRead": true,
            "flag": { "flagStatus": "flagged" }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_raw("{}", "application/json"))
        .expect(1)
        .mount(&e.server)
        .await;
    let flags = Flags {
        seen: true,
        flagged: true,
        ..Flags::default()
    };
    e.graph.set_flags(&e.store, id, flags).await.unwrap();
    assert_eq!(e.message(M1).flags, flags);
}

#[tokio::test]
async fn a_failed_flag_change_leaves_the_store_alone() {
    let e = env().await;
    e.mailbox().await;
    e.inbox().await;
    e.graph.sync(&e.store).await.unwrap();
    let id = e.store.find_by_graph_id(M1).unwrap().unwrap();
    Mock::given(method("PATCH"))
        .respond_with(ResponseTemplate::new(403).set_body_raw(
            r#"{"error":{"code":"ErrorAccessDenied","message":"no"}}"#,
            "application/json",
        ))
        .mount(&e.server)
        .await;
    let err = e
        .graph
        .set_flags(
            &e.store,
            id,
            Flags {
                seen: true,
                ..Flags::default()
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Api { status: 403, ref code } if code == "ErrorAccessDenied"));
    assert!(!e.message(M1).flags.seen);
}

#[tokio::test]
async fn moving_takes_the_id_the_server_returns() {
    let e = env().await;
    e.mailbox().await;
    e.inbox().await;
    e.graph.sync(&e.store).await.unwrap();
    let id = e.store.find_by_graph_id(M1).unwrap().unwrap();
    let projects = e
        .store
        .folders()
        .unwrap()
        .into_iter()
        .find(|f| f.name == "Projects")
        .unwrap();

    Mock::given(method("POST"))
        .and(path(format!("/me/messages/{M1}/move")))
        .and(body_json(
            serde_json::json!({ "destinationId": "projects-id" }),
        ))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_raw(r#"{"id":"AAMkAGI2TGuLNEW="}"#, "application/json"),
        )
        .expect(1)
        .mount(&e.server)
        .await;
    e.graph
        .move_message(&e.store, id, projects.id)
        .await
        .unwrap();
    let m = e.store.message(id).unwrap().unwrap();
    assert_eq!(m.folder_id, projects.id);
    assert_eq!(m.graph_id.as_deref(), Some("AAMkAGI2TGuLNEW="));
}

#[tokio::test]
async fn trash_moves_to_deleted_items_and_a_second_trash_deletes() {
    let e = env().await;
    e.mailbox().await;
    e.inbox().await;
    e.graph.sync(&e.store).await.unwrap();
    let id = e.store.find_by_graph_id(M1).unwrap().unwrap();

    Mock::given(method("POST"))
        .and(path(format!("/me/messages/{M1}/move")))
        .and(body_json(
            serde_json::json!({ "destinationId": "deleted-id" }),
        ))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_raw(format!(r#"{{"id":"{M1}"}}"#), "application/json"),
        )
        .expect(1)
        .mount(&e.server)
        .await;
    e.graph.trash(&e.store, id).await.unwrap();
    assert_eq!(
        e.store.message(id).unwrap().unwrap().folder_id,
        e.folder("trash").id
    );

    Mock::given(method("DELETE"))
        .and(path(format!("/me/messages/{M1}")))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&e.server)
        .await;
    e.graph.trash(&e.store, id).await.unwrap();
    assert!(e.store.message(id).unwrap().is_none());
}

#[tokio::test]
async fn send_mail_posts_the_message_as_base64_text() {
    let e = env().await;
    let raw = b"From: a@contoso.example\r\nTo: b@contoso.example\r\nSubject: Hi\r\n\r\nHello\r\n";
    Mock::given(method("POST"))
        .and(path("/me/sendMail"))
        .and(header("content-type", "text/plain"))
        .and(body_string(
            "RnJvbTogYUBjb250b3NvLmV4YW1wbGUNClRvOiBiQGNvbnRvc28uZXhhbXBsZQ0KU3ViamVjdDogSGkNCg0KSGVsbG8NCg==",
        ))
        .respond_with(ResponseTemplate::new(202))
        .expect(1)
        .mount(&e.server)
        .await;
    e.graph.send_mail(raw).await.unwrap();
}

#[tokio::test]
async fn the_inbox_goes_first_and_a_failing_folder_does_not_stop_the_rest() {
    let e = env().await;
    e.mailbox().await;
    e.inbox().await;
    // Sent Items and Junk Email sort after Inbox and Drafts; Drafts fails.
    Mock::given(method("GET"))
        .and(path("/me/mailFolders/drafts-id/messages/delta"))
        .respond_with(ResponseTemplate::new(404).set_body_raw(
            r#"{"error":{"code":"ErrorFolderNotFound","message":"gone"}}"#,
            "application/json",
        ))
        .with_priority(1)
        .mount(&e.server)
        .await;
    let report = e.graph.sync(&e.store).await.unwrap();
    assert_eq!(report.summary.added, 3);
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0].0, e.folder("drafts").id);
    assert_eq!(report.folders[0].0, e.folder("inbox").id);
    assert_eq!(report.folders.len(), 5);
    // Deleted Items sorts before Drafts and Inbox by name, yet the inbox was asked first.
    let order: Vec<String> = e
        .server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().ends_with("/messages/delta"))
        .map(|r| r.url.path().to_string())
        .collect();
    assert!(order[0].contains("inbox-id"));
}

#[tokio::test]
async fn an_interrupted_page_keeps_the_messages_already_fetched() {
    let e = env().await;
    e.mailbox().await;
    e.inbox().await;
    Mock::given(method("GET"))
        .and(path(format!("/me/messages/{M2}/$value")))
        .respond_with(ResponseTemplate::new(500).set_body_raw(
            r#"{"error":{"code":"ErrorInternalServerError","message":"x"}}"#,
            "application/json",
        ))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&e.server)
        .await;
    e.graph.sync_folders(&e.store).await.unwrap();
    let inbox = e.folder("inbox");
    assert!(e.graph.sync_folder(&e.store, inbox.id).await.is_err());
    assert!(e.store.find_by_graph_id(M1).unwrap().is_some());
    assert!(e.store.find_by_graph_id(M2).unwrap().is_none());

    let sum = e.graph.sync_folder(&e.store, inbox.id).await.unwrap();
    assert_eq!(sum.added, 2);
    let fetched = e
        .server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().ends_with(&format!("{M1}/$value")))
        .count();
    assert_eq!(fetched, 1);
}

#[tokio::test]
async fn an_edited_draft_is_downloaded_again() {
    let e = env().await;
    e.mailbox().await;
    let base = e.server.uri();
    let d = "AAMkDRAFT=";
    let delta = |token: &str, subject: &str| {
        format!(
            r#"{{"value":[{{"id":"{d}","subject":"{subject}","isRead":true,"isDraft":true}}],"@odata.deltaLink":"{base}/me/mailFolders/drafts-id/messages/delta?$deltatoken={token}"}}"#
        )
    };
    e.json(
        "/me/mailFolders/drafts-id/messages/delta",
        &[("$select", SELECT)],
        delta("d1", "First"),
    )
    .await;
    e.json(
        "/me/mailFolders/drafts-id/messages/delta",
        &[("$deltatoken", "d1")],
        delta("d2", "Second"),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(format!("/me/messages/{d}/$value")))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            fs::read(format!("{}/tests/fixtures/message_1.eml", e.manifest())).unwrap(),
            "message/rfc822",
        ))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&e.server)
        .await;
    e.graph.sync_folders(&e.store).await.unwrap();
    let drafts = e.folder("drafts");
    e.graph.sync_folder(&e.store, drafts.id).await.unwrap();
    assert_eq!(e.message(d).subject, "First");
    assert!(e.message(d).body_text.unwrap().contains("Notes from today"));

    e.mime(d, "message_3.eml").await;
    let sum = e.graph.sync_folder(&e.store, drafts.id).await.unwrap();
    assert_eq!(sum.updated, 1);
    let m = e.message(d);
    assert_eq!(m.subject, "Second");
    assert!(m.body_text.unwrap().contains("Three things"));
    assert!(m.flags.draft);
    assert_eq!(e.store.folder_graph_ids(drafts.id).unwrap().len(), 1);
}

#[tokio::test]
async fn folders_keep_their_parents_and_system_folders_are_left_out() {
    let e = env().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/me/mailFolders/[a-z]+$"))
        .respond_with(ResponseTemplate::new(404).set_body_raw(
            r#"{"error":{"code":"ErrorFolderNotFound","message":"missing"}}"#,
            "application/json",
        ))
        .with_priority(10)
        .mount(&e.server)
        .await;
    e.json(
        "/me/mailFolders/delta",
        &[],
        fixture(&e, "folders_delta_tree.json"),
    )
    .await;
    e.graph.sync_folders(&e.store).await.unwrap();
    let mut names: Vec<_> = e
        .store
        .folders()
        .unwrap()
        .into_iter()
        .map(|f| f.name)
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["Inbox", "Inbox/2026", "Sent Items", "Sent Items/2026"]
    );
}

#[tokio::test]
async fn an_unchanged_folder_list_does_not_look_up_the_roles_again() {
    let e = env().await;
    e.mailbox().await;
    e.graph.sync_folders(&e.store).await.unwrap();
    e.json(
        "/me/mailFolders/delta",
        &[("$deltatoken", "folders-1")],
        r#"{"value":[{"id":"inbox-id","displayName":"Inbox"}],"@odata.deltaLink":"http://x/me/mailFolders/delta?$deltatoken=folders-1"}"#.replace("http://x", &e.server.uri()),
    )
    .await;
    let before = e.server.received_requests().await.unwrap().len();
    e.graph.sync_folders(&e.store).await.unwrap();
    let requests = e.server.received_requests().await.unwrap();
    assert_eq!(requests.len() - before, 1);
}

#[tokio::test]
async fn a_removed_folder_takes_its_messages_with_it() {
    let e = env().await;
    e.mailbox().await;
    e.inbox().await;
    e.graph.sync(&e.store).await.unwrap();
    e.json(
        "/me/mailFolders/delta",
        &[("$deltatoken", "folders-1")],
        format!(
            r#"{{"value":[{{"id":"inbox-id","@removed":{{"reason":"deleted"}}}}],"@odata.deltaLink":"{}/me/mailFolders/delta?$deltatoken=folders-2"}}"#,
            e.server.uri()
        ),
    )
    .await;
    e.graph.sync_folders(&e.store).await.unwrap();
    assert!(e.store.find_by_graph_id(M1).unwrap().is_none());
    assert!(e.store.find_by_graph_id(M3).unwrap().is_none());
}

#[tokio::test]
async fn an_expired_folder_link_lists_the_folders_again() {
    let e = env().await;
    e.mailbox().await;
    e.graph.sync_folders(&e.store).await.unwrap();
    Mock::given(method("GET"))
        .and(path("/me/mailFolders/delta"))
        .and(query_param("$deltatoken", "folders-1"))
        .respond_with(ResponseTemplate::new(410).set_body_raw(
            fixture(&e, "error_sync_state_not_found.json"),
            "application/json",
        ))
        .with_priority(1)
        .mount(&e.server)
        .await;
    e.store
        .upsert_remote_folder("stale-id", "Stale", None)
        .unwrap();
    e.graph.sync_folders(&e.store).await.unwrap();
    let names: Vec<_> = e
        .store
        .folders()
        .unwrap()
        .into_iter()
        .map(|f| f.name)
        .collect();
    assert_eq!(names.len(), 6);
    assert!(!names.contains(&"Stale".to_string()));
}

#[tokio::test]
async fn an_interrupted_folder_listing_still_sweeps_when_it_is_repeated() {
    let e = env().await;
    e.mailbox().await;
    e.store
        .upsert_remote_folder("stale-id", "Stale", None)
        .unwrap();
    Mock::given(method("GET"))
        .and(path("/me/mailFolders/delta"))
        .and(query_param("$skiptoken", "folders-p2"))
        .respond_with(ResponseTemplate::new(500).set_body_raw(
            r#"{"error":{"code":"ErrorInternalServerError","message":"x"}}"#,
            "application/json",
        ))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&e.server)
        .await;
    assert!(e.graph.sync_folders(&e.store).await.is_err());
    e.graph.sync_folders(&e.store).await.unwrap();
    let names: Vec<_> = e
        .store
        .folders()
        .unwrap()
        .into_iter()
        .map(|f| f.name)
        .collect();
    assert!(!names.contains(&"Stale".to_string()));
    assert_eq!(names.len(), 6);
}

#[tokio::test]
async fn a_message_too_big_for_sendmail_is_refused_before_the_request() {
    let e = env().await;
    let raw = vec![b'x'; 3_100_000];
    assert!(matches!(
        e.graph.send_mail(&raw).await,
        Err(Error::TooLarge)
    ));
    assert!(e.server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_message_deleted_before_its_body_is_fetched_is_skipped() {
    let e = env().await;
    e.mailbox().await;
    e.inbox().await;
    // M2 answers 404 on its body; the other two still arrive.
    Mock::given(method("GET"))
        .and(path(format!("/me/messages/{M2}/$value")))
        .respond_with(ResponseTemplate::new(404).set_body_raw(
            r#"{"error":{"code":"ErrorItemNotFound","message":"gone"}}"#,
            "application/json",
        ))
        .with_priority(1)
        .mount(&e.server)
        .await;
    let sum = e.graph.sync(&e.store).await.unwrap().summary;
    assert_eq!(sum.added, 2);
    assert!(e.store.find_by_graph_id(M2).unwrap().is_none());
}
