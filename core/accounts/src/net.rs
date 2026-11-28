use std::time::Duration;

use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use rustls::ClientConfig;
use rustls_platform_verifier::BuilderVerifierExt;

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
                // The system's verifier, since phones have no root files to load.
                // Android needs two inits from the native layer first: rustls_platform_verifier's,
                // and ndk_context's, which the DNS config below reads through JNI (it also
                // needs ACCESS_NETWORK_STATE, or SRV lookups quietly find nothing).
                .use_preconfigured_tls(tls_config())
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

fn tls_config() -> ClientConfig {
    ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .with_platform_verifier()
        .expect("platform verifier")
        .with_no_client_auth()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn client_builds_with_the_platform_verifier() {
        let _ = SystemNetwork::new();
    }
}
