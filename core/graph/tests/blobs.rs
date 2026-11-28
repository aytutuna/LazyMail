use base64::{engine::general_purpose::STANDARD, Engine};
use lazymail_accounts::{Resource, StaticTokens};
use lazymail_graph::Graph;
use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn env() -> (MockServer, Graph<StaticTokens>) {
    let server = MockServer::start().await;
    let tokens = StaticTokens::default();
    tokens.set("acct", Resource::Graph, Ok("tok".into()));
    let graph = Graph::with_base_url("acct", tokens, &server.uri());
    (server, graph)
}

fn json(body: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(body.to_string(), "application/json")
}

#[tokio::test]
async fn the_folder_is_found_or_made() {
    let (server, graph) = env().await;
    Mock::given(method("GET"))
        .and(path("/me/mailFolders"))
        .and(query_param("$filter", "displayName eq 'Alazy'"))
        .respond_with(json(serde_json::json!({ "value": [{ "id": "F1" }] })))
        .mount(&server)
        .await;
    assert_eq!(graph.blob_folder("Alazy").await.unwrap(), "F1");

    let (server, graph) = env().await;
    Mock::given(method("GET"))
        .and(path("/me/mailFolders"))
        .respond_with(json(serde_json::json!({ "value": [] })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/me/mailFolders"))
        .and(body_json(serde_json::json!({ "displayName": "Alazy" })))
        .respond_with(json(serde_json::json!({ "id": "F2" })))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(graph.blob_folder("Alazy").await.unwrap(), "F2");
}

#[tokio::test]
async fn a_listing_follows_its_pages_in_order() {
    let (server, graph) = env().await;
    let next = format!("{}/me/mailFolders/F1/messages?page=2", server.uri());
    Mock::given(method("GET"))
        .and(path("/me/mailFolders/F1/messages"))
        .and(query_param("page", "2"))
        .respond_with(json(serde_json::json!({ "value": [{ "id": "C" }] })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/me/mailFolders/F1/messages"))
        .and(query_param("$orderby", "createdDateTime"))
        .respond_with(json(serde_json::json!({
            "value": [{ "id": "A" }, { "id": "B" }],
            "@odata.nextLink": next,
        })))
        .mount(&server)
        .await;
    assert_eq!(graph.list_blobs("F1").await.unwrap(), ["A", "B", "C"]);
}

#[tokio::test]
async fn a_message_is_stored_and_read_back_as_text() {
    let (server, graph) = env().await;
    let data = [0u8, 1, 2, 255, 128];
    let b64 = STANDARD.encode(data);
    Mock::given(method("POST"))
        .and(path("/me/mailFolders/F1/messages"))
        .and(body_json(serde_json::json!({
            "subject": "Alazy settings, do not delete",
            "body": { "contentType": "text", "content": b64 },
            "isRead": true,
        })))
        .respond_with(json(serde_json::json!({ "id": "M1" })))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        graph
            .append_blob("F1", "Alazy settings, do not delete", &data)
            .await
            .unwrap(),
        "M1"
    );

    // Exchange wraps long lines and may encode the part.
    let (head, tail) = b64.split_at(4);
    let mime = format!(
        "Subject: s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{head}\r\n{tail}\r\n"
    );
    Mock::given(method("GET"))
        .and(path("/me/messages/M1/$value"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(mime, "message/rfc822"))
        .mount(&server)
        .await;
    assert_eq!(graph.fetch_blob("M1").await.unwrap(), Some(data.to_vec()));
}

#[tokio::test]
async fn a_message_removed_elsewhere_is_none_and_deleting_it_is_fine() {
    let (server, graph) = env().await;
    Mock::given(method("GET"))
        .and(path("/me/messages/GONE/$value"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/me/messages/GONE"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    assert_eq!(graph.fetch_blob("GONE").await.unwrap(), None);
    graph.delete_blob("GONE").await.unwrap();
}
