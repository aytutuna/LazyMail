use std::future::Future;

use crate::provider::{Endpoint, Login, Provider, Security, ServerSettings};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

/// The two lookups discovery needs, so tests can answer them from fixtures. Failures
/// of any kind are answered with nothing and discovery moves on.
pub trait Network: Sync {
    /// Body of a successful HTTPS response.
    fn get(&self, url: &str) -> impl Future<Output = Option<String>> + Send;
    fn srv(&self, name: &str) -> impl Future<Output = Vec<SrvRecord>> + Send;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Builtin,
    Ispdb,
    ProviderAutoconfig,
    Srv,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub settings: ServerSettings,
    pub source: Source,
    /// DNS is not verified, so an SRV answer pointing outside the address's own domain
    /// must be shown to the person before the password is sent there (RFC 6186 section 6).
    pub needs_confirmation: bool,
}

/// Finds server settings: the built-in table, Mozilla's ISPDB, the provider's own
/// autoconfig, then DNS SRV. `None` means the person types them.
pub async fn discover(net: &impl Network, address: &str) -> Option<Found> {
    let domain = valid_domain(address)?;
    if let Some(settings) = Provider::detect(address).settings() {
        return Some(Found {
            settings,
            source: Source::Builtin,
            needs_confirmation: false,
        });
    }

    let ispdb = format!("https://autoconfig.thunderbird.net/v1.1/{domain}");
    let own = [
        format!(
            "https://autoconfig.{domain}/mail/config-v1.1.xml?emailaddress={}",
            percent_encode(address)
        ),
        format!("https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml"),
    ];
    if let Some(settings) = from_xml(net.get(&ispdb).await, &domain) {
        return Some(Found {
            settings,
            source: Source::Ispdb,
            needs_confirmation: false,
        });
    }
    for url in &own {
        if let Some(settings) = from_xml(net.get(url).await, &domain) {
            return Some(Found {
                settings,
                source: Source::ProviderAutoconfig,
                needs_confirmation: false,
            });
        }
    }
    srv_settings(net, &domain).await.map(|settings| Found {
        needs_confirmation: ![&settings.imap, &settings.smtp]
            .iter()
            .all(|e| within(&e.host, &domain)),
        settings,
        source: Source::Srv,
    })
}

fn from_xml(body: Option<String>, domain: &str) -> Option<ServerSettings> {
    parse_autoconfig(&body?, domain)
}

/// Reads a Mozilla autoconfig document (config-v1.1). Takes the safest IMAP and SMTP
/// server it lists that uses a password; servers that need OAuth or a login pattern
/// we cannot fill in are skipped.
pub fn parse_autoconfig(xml: &str, domain: &str) -> Option<ServerSettings> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let provider = doc
        .descendants()
        .find(|n| n.has_tag_name("emailProvider"))?;
    let pick = |tag: &str, kind: &str| {
        provider
            .children()
            .filter(|n| n.has_tag_name(tag) && n.attribute("type") == Some(kind))
            .filter_map(|n| endpoint(n, domain))
            .min_by_key(|e| e.security != Security::Tls)
    };
    Some(ServerSettings {
        imap: pick("incomingServer", "imap")?,
        smtp: pick("outgoingServer", "smtp")?,
        files_sent: false,
        gmail: false,
        max_connections: 4,
    })
}

fn endpoint(node: roxmltree::Node, domain: &str) -> Option<Endpoint> {
    let text = |tag: &str| {
        node.children()
            .find(|n| n.has_tag_name(tag))
            .and_then(|n| n.text())
            .map(str::trim)
    };
    let host = text("hostname")?.replace("%EMAILDOMAIN%", domain);
    if host.is_empty() || host.contains('%') {
        return None;
    }
    let security = match text("socketType")? {
        "SSL" => Security::Tls,
        "STARTTLS" => Security::StartTls,
        _ => return None,
    };
    let login = match text("username")? {
        "%EMAILADDRESS%" => Login::Address,
        "%EMAILLOCALPART%" => Login::LocalPart,
        _ => return None,
    };
    let password_auth = |a: &str| matches!(a, "password-cleartext" | "plain");
    let mut auth = node
        .children()
        .filter(|n| n.has_tag_name("authentication"))
        .filter_map(|n| n.text())
        .map(str::trim)
        .peekable();
    if auth.peek().is_some() && !auth.any(password_auth) {
        return None;
    }
    Some(Endpoint {
        host,
        port: text("port")?.parse().ok()?,
        security,
        login,
    })
}

// RFC 6186: implicit TLS services first, then the STARTTLS ones.
async fn srv_settings(net: &impl Network, domain: &str) -> Option<ServerSettings> {
    let imap = srv_endpoint(net, domain, "_imaps", "_imap").await?;
    let smtp = srv_endpoint(net, domain, "_submissions", "_submission").await?;
    Some(ServerSettings {
        imap,
        smtp,
        files_sent: false,
        gmail: false,
        max_connections: 4,
    })
}

async fn srv_endpoint(
    net: &impl Network,
    domain: &str,
    tls_service: &str,
    starttls_service: &str,
) -> Option<Endpoint> {
    for (service, security) in [
        (tls_service, Security::Tls),
        (starttls_service, Security::StartTls),
    ] {
        let records = net.srv(&format!("{service}._tcp.{domain}")).await;
        // A target of "." says the service is deliberately not offered.
        let best = records
            .into_iter()
            .filter(|r| !r.target.trim_end_matches('.').is_empty())
            .min_by_key(|r| (r.priority, std::cmp::Reverse(r.weight)));
        if let Some(r) = best {
            return Some(Endpoint {
                host: r.target.trim_end_matches('.').to_string(),
                port: r.port,
                security,
                login: Login::Address,
            });
        }
    }
    None
}

fn within(host: &str, domain: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// The domain of an address, only if it is safe to put in a URL or a DNS name.
fn valid_domain(address: &str) -> Option<String> {
    let (local, domain) = address.rsplit_once('@')?;
    let domain = domain.trim().to_ascii_lowercase();
    let ok = !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with(['.', '-'])
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    ok.then_some(domain)
}

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct Fixtures {
        pages: HashMap<String, String>,
        srv: HashMap<String, Vec<SrvRecord>>,
        asked: Mutex<Vec<String>>,
    }

    impl Network for Fixtures {
        async fn get(&self, url: &str) -> Option<String> {
            self.asked.lock().unwrap().push(url.to_string());
            self.pages.get(url).cloned()
        }
        async fn srv(&self, name: &str) -> Vec<SrvRecord> {
            self.asked.lock().unwrap().push(name.to_string());
            self.srv.get(name).cloned().unwrap_or_default()
        }
    }

    const CONFIG: &str = r#"<?xml version="1.0"?>
<clientConfig version="1.1">
  <emailProvider id="example.org">
    <incomingServer type="pop3">
      <hostname>pop.example.org</hostname><port>995</port><socketType>SSL</socketType>
      <username>%EMAILADDRESS%</username><authentication>password-cleartext</authentication>
    </incomingServer>
    <incomingServer type="imap">
      <hostname>imap.%EMAILDOMAIN%</hostname><port>143</port><socketType>STARTTLS</socketType>
      <username>%EMAILLOCALPART%</username><authentication>password-cleartext</authentication>
    </incomingServer>
    <incomingServer type="imap">
      <hostname>imap.example.org</hostname><port>993</port><socketType>SSL</socketType>
      <username>%EMAILADDRESS%</username><authentication>password-cleartext</authentication>
    </incomingServer>
    <incomingServer type="imap">
      <hostname>oauth.example.org</hostname><port>993</port><socketType>SSL</socketType>
      <username>%EMAILADDRESS%</username><authentication>OAuth2</authentication>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>smtp.example.org</hostname><port>465</port><socketType>SSL</socketType>
      <username>%EMAILADDRESS%</username><authentication>password-cleartext</authentication>
    </outgoingServer>
  </emailProvider>
</clientConfig>"#;

    fn pages(url: &str, body: &str) -> Fixtures {
        let mut f = Fixtures::default();
        f.pages.insert(url.to_string(), body.to_string());
        f
    }

    #[tokio::test]
    async fn named_providers_need_no_network() {
        let f = Fixtures::default();
        let found = discover(&f, "me@hotmail.co.uk").await.unwrap();
        assert_eq!(found.source, Source::Builtin);
        assert_eq!(found.settings.imap.host, "outlook.office365.com");
        assert!(f.asked.lock().unwrap().is_empty());
        let gmail = discover(&f, "x@gmail.com").await.unwrap().settings;
        assert!(gmail.gmail && gmail.files_sent);
        assert_eq!(gmail.max_connections, 3);
    }

    #[tokio::test]
    async fn ispdb_wins_and_prefers_implicit_tls() {
        let f = pages(
            "https://autoconfig.thunderbird.net/v1.1/example.org",
            CONFIG,
        );
        let found = discover(&f, "Ann@Example.org").await.unwrap();
        assert_eq!(found.source, Source::Ispdb);
        assert_eq!(found.settings.imap.host, "imap.example.org");
        assert_eq!(found.settings.imap.security, Security::Tls);
        assert_eq!(found.settings.smtp.port, 465);
    }

    #[tokio::test]
    async fn provider_autoconfig_comes_after_ispdb() {
        let f = pages(
            "https://autoconfig.example.org/mail/config-v1.1.xml?emailaddress=ann%40example.org",
            CONFIG,
        );
        let found = discover(&f, "ann@example.org").await.unwrap();
        assert_eq!(found.source, Source::ProviderAutoconfig);

        let f = pages(
            "https://example.org/.well-known/autoconfig/mail/config-v1.1.xml",
            CONFIG,
        );
        let found = discover(&f, "ann@example.org").await.unwrap();
        assert_eq!(found.source, Source::ProviderAutoconfig);
    }

    #[test]
    fn placeholders_are_filled_in() {
        let xml = r#"<clientConfig><emailProvider id="e">
          <incomingServer type="imap"><hostname>imap.%EMAILDOMAIN%</hostname><port>143</port>
            <socketType>STARTTLS</socketType><username>%EMAILLOCALPART%</username></incomingServer>
          <outgoingServer type="smtp"><hostname>smtp.e.org</hostname><port>587</port>
            <socketType>STARTTLS</socketType><username>%EMAILADDRESS%</username></outgoingServer>
        </emailProvider></clientConfig>"#;
        let s = parse_autoconfig(xml, "e.org").unwrap();
        assert_eq!(s.imap.host, "imap.e.org");
        assert_eq!(s.imap.security, Security::StartTls);
        assert_eq!(s.imap.login.resolve("ann@e.org"), "ann");
        assert_eq!(s.smtp.login.resolve("ann@e.org"), "ann@e.org");
    }

    #[test]
    fn oauth_only_and_plain_servers_are_refused() {
        let xml = r#"<clientConfig><emailProvider id="e">
          <incomingServer type="imap"><hostname>imap.e.org</hostname><port>993</port>
            <socketType>SSL</socketType><username>%EMAILADDRESS%</username>
            <authentication>OAuth2</authentication></incomingServer>
          <outgoingServer type="smtp"><hostname>smtp.e.org</hostname><port>25</port>
            <socketType>plain</socketType><username>%EMAILADDRESS%</username></outgoingServer>
        </emailProvider></clientConfig>"#;
        assert_eq!(parse_autoconfig(xml, "e.org"), None);
        assert_eq!(parse_autoconfig("not xml", "e.org"), None);
    }

    fn srv(priority: u16, weight: u16, port: u16, target: &str) -> SrvRecord {
        SrvRecord {
            priority,
            weight,
            port,
            target: target.to_string(),
        }
    }

    #[tokio::test]
    async fn srv_picks_priority_then_weight_and_tls_first() {
        let mut f = Fixtures::default();
        f.srv.insert(
            "_imaps._tcp.example.net".into(),
            vec![
                srv(20, 5, 993, "slow.example.net."),
                srv(10, 1, 993, "b.example.net."),
                srv(10, 9, 993, "a.example.net."),
            ],
        );
        f.srv.insert(
            "_submission._tcp.example.net".into(),
            vec![srv(0, 1, 587, "smtp.example.net.")],
        );
        let found = discover(&f, "ann@example.net").await.unwrap();
        assert_eq!(found.source, Source::Srv);
        assert!(!found.needs_confirmation);
        assert_eq!(found.settings.imap.host, "a.example.net");
        assert_eq!(found.settings.imap.security, Security::Tls);
        assert_eq!(found.settings.smtp.security, Security::StartTls);
        assert_eq!(found.settings.smtp.port, 587);
    }

    #[tokio::test]
    async fn srv_target_outside_the_domain_needs_confirmation() {
        let mut f = Fixtures::default();
        f.srv.insert(
            "_imaps._tcp.example.net".into(),
            vec![srv(0, 1, 993, "imap.elsewhere.org.")],
        );
        f.srv.insert(
            "_submissions._tcp.example.net".into(),
            vec![srv(0, 1, 465, "smtp.example.net.")],
        );
        let found = discover(&f, "ann@example.net").await.unwrap();
        assert!(found.needs_confirmation);
        let mut f = Fixtures::default();
        f.srv.insert(
            "_imaps._tcp.example.net".into(),
            vec![srv(0, 1, 993, "notexample.net.")],
        );
        f.srv.insert(
            "_submissions._tcp.example.net".into(),
            vec![srv(0, 1, 465, "smtp.example.net.")],
        );
        assert!(
            discover(&f, "ann@example.net")
                .await
                .unwrap()
                .needs_confirmation
        );
    }

    #[tokio::test]
    async fn srv_dot_target_means_not_offered() {
        let mut f = Fixtures::default();
        f.srv
            .insert("_imaps._tcp.example.net".into(), vec![srv(0, 0, 0, ".")]);
        f.srv.insert(
            "_submissions._tcp.example.net".into(),
            vec![srv(0, 1, 465, "smtp.example.net.")],
        );
        assert_eq!(discover(&f, "ann@example.net").await, None);
    }

    #[tokio::test]
    async fn nothing_found_and_bad_addresses_give_none() {
        let f = Fixtures::default();
        assert_eq!(discover(&f, "ann@example.net").await, None);
        assert_eq!(discover(&f, "ann@exa/mple.net").await, None);
        assert_eq!(discover(&f, "no-at-sign").await, None);
        assert_eq!(f.asked.lock().unwrap().len(), 3 + 2);
    }

    #[test]
    fn detect_does_not_take_lookalikes() {
        assert_eq!(Provider::detect("a@live.mycompany.com"), Provider::Other);
        assert_eq!(Provider::detect("a@hotmail.fr"), Provider::Outlook);
        assert_eq!(Provider::detect("a@live.co.uk"), Provider::Outlook);
        assert_eq!(Provider::detect("a@yahoo.co.uk"), Provider::Yahoo);
        assert_eq!(Provider::detect("a@yahoo.co.jp"), Provider::Other);
        assert_eq!(Provider::detect("a@icloud.com"), Provider::ICloud);
        assert_eq!(Provider::detect("a@pm.me"), Provider::ProtonBridge);
    }
}
