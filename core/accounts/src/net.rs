use std::time::Duration;

use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;

use crate::autoconfig::{Network, SrvRecord};

const MAX_BODY: usize = 256 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);

/// Real lookups for discovery: HTTPS through reqwest, SRV through the system's DNS.
pub struct SystemNetwork {
    http: reqwest::Client,
    dns: Option<TokioResolver>,
}

impl SystemNetwork {
    pub fn new() -> SystemNetwork {
        SystemNetwork {
            http: reqwest::Client::builder()
                .timeout(TIMEOUT)
                .https_only(true)
                .build()
                .expect("http client"),
            dns: TokioResolver::builder_tokio()
                .ok()
                .and_then(|b| b.build().ok()),
        }
    }
}

impl Default for SystemNetwork {
    fn default() -> Self {
        Self::new()
    }
}

impl Network for SystemNetwork {
    async fn get(&self, url: &str) -> Option<String> {
        let mut response = self
            .http
            .get(url)
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.ok()? {
            body.extend_from_slice(&chunk);
            if body.len() > MAX_BODY {
                return None;
            }
        }
        String::from_utf8(body).ok()
    }

    async fn srv(&self, name: &str) -> Vec<SrvRecord> {
        let Some(dns) = &self.dns else {
            return Vec::new();
        };
        let Ok(lookup) = dns.srv_lookup(name).await else {
            return Vec::new();
        };
        lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::SRV(r) => Some(SrvRecord {
                    priority: r.priority,
                    weight: r.weight,
                    port: r.port,
                    target: r.target.to_utf8(),
                }),
                _ => None,
            })
            .collect()
    }
}
