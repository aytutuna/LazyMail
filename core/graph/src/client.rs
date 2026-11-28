use std::time::Duration;

use lazymail_accounts::{Resource, TokenError, TokenSource};
use reqwest::header::{HeaderValue, AUTHORIZATION, RETRY_AFTER};
use reqwest::{Client, RequestBuilder, Response, StatusCode, Url};
use rustls::ClientConfig;
use rustls_platform_verifier::BuilderVerifierExt;
use serde::de::DeserializeOwned;

pub const BASE_URL: &str = "https://graph.microsoft.com/v1.0";

/// A longer Retry-After than this is handed back to the caller to schedule.
const MAX_WAIT: Duration = Duration::from_secs(60);
const RETRIES: u32 = 3;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Idle time between reads, so a large message on a slow link is not cut off.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A 401, or no usable refresh token.
    #[error("sign-in needed")]
    NeedsSignIn,
    /// 429 or 503 that kept coming; try again after the delay.
    #[error("throttled, retry in {0:?}")]
    Throttled(Duration),
    /// The delta link is too old; the folder has to be downloaded again.
    #[error("sync state expired")]
    SyncStateGone,
    #[error("graph error {status}: {code}")]
    Api { status: u16, code: String },
    #[error("token request failed: {0}")]
    Token(String),
    #[error("unexpected response: {0}")]
    BadResponse(String),
    #[error("no such folder or message")]
    NotFound,
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Store(#[from] lazymail_store::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Mail for one Microsoft 365 account through Microsoft Graph.
pub struct Graph<T> {
    http: Client,
    base: String,
    account_id: String,
    tokens: T,
}

impl<T: TokenSource> Graph<T> {
    pub fn new(account_id: &str, tokens: T) -> Graph<T> {
        Graph::with_base_url(account_id, tokens, BASE_URL)
    }

    /// For tests against a local server; links in responses must stay under `base`.
    pub fn with_base_url(account_id: &str, tokens: T, base: &str) -> Graph<T> {
        Graph {
            http: Client::builder()
                .use_preconfigured_tls(tls_config())
                .connect_timeout(CONNECT_TIMEOUT)
                .read_timeout(READ_TIMEOUT)
                .build()
                .expect("http client"),
            base: base.trim_end_matches('/').to_string(),
            account_id: account_id.to_string(),
            tokens,
        }
    }

    pub(crate) fn url(&self, segments: &[&str], query: &[(&str, &str)]) -> Url {
        let mut url = Url::parse(&self.base).expect("base url");
        url.path_segments_mut()
            .expect("base url has a path")
            .extend(segments);
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        url
    }

    /// A nextLink or deltaLink is followed only while it stays under the base, since every
    /// request carries the bearer token.
    pub(crate) fn link(&self, link: &str) -> Result<Url> {
        if !link.starts_with(&format!("{}/", self.base)) {
            return Err(Error::BadResponse(format!("link outside the API: {link}")));
        }
        Url::parse(link).map_err(|e| Error::BadResponse(e.to_string()))
    }

    /// Sends the request with a fresh token, waiting out 429 and 503 as the server asks.
    pub(crate) async fn send(&self, build: impl Fn(&Client) -> RequestBuilder) -> Result<Response> {
        let mut attempt = 0;
        loop {
            let token = self
                .tokens
                .access_token(&self.account_id, Resource::Graph)
                .await
                .map_err(|e| match e {
                    TokenError::InteractionRequired => Error::NeedsSignIn,
                    TokenError::Failed(m) => Error::Token(m),
                })?;
            let mut bearer = HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| Error::Token("token is not a header value".into()))?;
            bearer.set_sensitive(true);
            let resp = build(&self.http)
                .header(AUTHORIZATION, bearer)
                .header("Prefer", "IdType=\"ImmutableId\", odata.maxpagesize=50")
                .send()
                .await?;
            let status = resp.status();
            if status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::SERVICE_UNAVAILABLE
            {
                let wait = retry_after(&resp).unwrap_or(Duration::from_secs(5 << attempt));
                if attempt >= RETRIES || wait > MAX_WAIT {
                    return Err(Error::Throttled(wait));
                }
                attempt += 1;
                tokio::time::sleep(wait).await;
                continue;
            }
            return check(resp).await;
        }
    }

    pub(crate) async fn get_json<D: DeserializeOwned>(&self, url: Url) -> Result<D> {
        let resp = self.send(|c| c.get(url.clone())).await?;
        resp.json()
            .await
            .map_err(|e| Error::BadResponse(e.to_string()))
    }
}

async fn check(resp: Response) -> Result<Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    if status == StatusCode::UNAUTHORIZED {
        return Err(Error::NeedsSignIn);
    }
    let code = resp
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|v| v["error"]["code"].as_str().map(str::to_string))
        .unwrap_or_default();
    Err(match (status, code.as_str()) {
        (StatusCode::GONE, _) | (_, "syncStateNotFound" | "resyncRequired") => Error::SyncStateGone,
        (StatusCode::NOT_FOUND, _) => Error::NotFound,
        _ => Error::Api {
            status: status.as_u16(),
            code,
        },
    })
}

fn retry_after(resp: &Response) -> Option<Duration> {
    resp.headers()
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn tls_config() -> ClientConfig {
    ClientConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .with_platform_verifier()
        .expect("platform verifier")
        .with_no_client_auth()
}
